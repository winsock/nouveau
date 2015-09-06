/*
 * Copyright (c) 2015, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "priv.h"

#include <core/gpuobj.h>
#include <subdev/mmu.h>

struct gm20b_pmu {
	struct nvkm_pmu base;
};
#define gm20b_pmu(p) container_of((p), struct gm20b_pmu, base.subdev)

#define PMU_DMEM_ADDR_MASK	0xfffc
static int
pmu_copy_from_dmem(struct nvkm_device *device, u32 src, void *dst, u32 size,
		   u8 port)
{
	/* Number of full words */
	u32 w_size = size / sizeof(u32);
	/* Number of extra bytes */
	u32 b_size = size % sizeof(u32);
	int i;

	if (size == 0)
		return 0;

	if (src & 0x3) {
		nvdev_error(device, "destination offset not aligned\n");
		return -EINVAL;
	}

	src &= PMU_DMEM_ADDR_MASK;

	mutex_lock(&device->mutex);

	nvkm_wr32(device, (0x10a1c0 + (port * 8)), (src | (0x1 << 25)));

	for (i = 0; i < w_size; i++)
		((u32 *)dst)[i] = nvkm_rd32(device, (0x10a1c4 + (port * 8)));

	if (b_size != 0) {
		u32 data = nvkm_rd32(device, (0x10a1c4 + (port * 8)));
		memcpy(((u32 *)dst) + w_size, &data, b_size);
	}

	mutex_unlock(&device->mutex);

	return 0;
}


static void
pmu_disable_irq(struct nvkm_device *device)
{
	nvkm_mask(device, 0x644, 0x1000000, 0x0);
	nvkm_mask(device, 0x640, 0x1000000, 0x0);
	nvkm_wr32(device, 0x10a014, 0xff);
}

static void
pmu_enable_irq(struct nvkm_device *device)
{
	nvkm_wr32(device, 0x10a010, 0xff);
	nvkm_mask(device, 0x640, 0x1000000, 0x1000000);
	nvkm_mask(device, 0x644, 0x1000000, 0x1000000);
}

static void
gm20b_pmu_intr(struct nvkm_subdev *subdev)
{
	struct gm20b_pmu *pmu = gm20b_pmu(subdev);
	struct nvkm_device *device = subdev->device;
	u32 intr, mask;

	mask = nvkm_rd32(device, 0x10a018) & nvkm_rd32(device, 0x10a01c);
	intr = nvkm_rd32(device, 0x10a008) & mask;

	pmu_disable_irq(device);

	if (!intr) {
		nvkm_wr32(device, 0x10a004, intr);
		nvkm_error(subdev, "pmu state off\n");
		pmu_enable_irq(device);
	}

	if (intr & 0x10)
		nvkm_error(subdev, "pmu halt interrupt not implemented\n");

	if (intr & 0x20) {
		nvkm_error(subdev, "extern interrupt not implemented\n");
		nvkm_mask(device, 0x10a16c, (0x1 << 31), 0x00000000);
	}

	if (intr & 0x40)
		schedule_work(&pmu->base.recv.work);

	nvkm_wr32(device, 0x10a004, intr);
}

struct pmu_hdr {
	u8 unit_id;
	u8 size;
	u8 ctrl_flags;
	u8 seq_id;
};

#define PMU_QUEUE_COUNT  5
struct pmu_init_msg_pmu_gk20a {
	u8 msg_type;
	u8 pad;
	u16  os_debug_entry_point;

	struct {
		u16 size;
		u16 offset;
		u8  index;
		u8  pad;
	} queue_info[PMU_QUEUE_COUNT];

	u16 sw_managed_area_offset;
	u16 sw_managed_area_size;
};

struct pmu_init_msg {
	union {
		u8 msg_type;
		struct pmu_init_msg_pmu_gk20a pmu_init_gk20a;
	};
};

enum {
	PMU_RC_MSG_TYPE_UNHANDLED_CMD = 0,
};

struct pmu_rc_msg_unhandled_cmd {
	u8 msg_type;
	u8 unit_id;
};

struct pmu_rc_msg {
	u8 msg_type;
	struct pmu_rc_msg_unhandled_cmd unhandled_cmd;
};

/*pmu generic msg format*/
struct pmu_msg {
	struct pmu_hdr hdr;
	union {
		struct pmu_init_msg init;
		struct pmu_rc_msg rc;
	} msg;
};

#define PMU_UNIT_REWIND		(0x00)
#define PMU_UNIT_PG		(0x03)
#define PMU_UNIT_INIT		(0x07)
#define PMU_UNIT_PERFMON	(0x12)
#define PMU_UNIT_THERM		(0x1B)
#define PMU_UNIT_RC		(0x1F)
#define PMU_UNIT_NULL		(0x20)
#define PMU_UNIT_END		(0x23)
#define PMU_UNIT_TEST_START	(0xFE)
#define PMU_UNIT_END_SIM	(0xFF)
#define PMU_UNIT_TEST_END	(0xFF)

enum {
	PMU_INIT_MSG_TYPE_PMU_INIT = 0,
};

#define PMU_DMEM_ALIGNMENT 4

static int
pmu_process_init_msg(struct gm20b_pmu *pmu, struct pmu_msg *msg)
{
	struct nvkm_subdev *subdev = &pmu->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 tail;
	int err;

	tail = nvkm_rd32(device, 0x10a4cc);

	err = pmu_copy_from_dmem(device, tail, &msg->hdr, sizeof(msg->hdr), 0);
	if (err)
		return err;

	if (msg->hdr.unit_id != PMU_UNIT_INIT) {
		nvkm_error(subdev, "expecting init msg\n");
		return -EINVAL;
	}

	err = pmu_copy_from_dmem(device, tail + sizeof(msg->hdr), &msg->msg,
				 msg->hdr.size - sizeof(msg->hdr), 0);
	if (err)
		return err;

	if (msg->msg.init.msg_type != PMU_INIT_MSG_TYPE_PMU_INIT) {
		nvkm_error(subdev, "expecting init msg\n");
		return -EINVAL;
	}

	tail += ALIGN(msg->hdr.size, PMU_DMEM_ALIGNMENT);
	nvkm_wr32(device, 0x10a4cc, tail);

	nvkm_info(&pmu->base.subdev, "init msg processed\n");

	return 0;
}

static void
pmu_process_message(struct work_struct *work)
{
	struct gm20b_pmu *pmu = container_of(work, struct gm20b_pmu,
					     base.recv.work);
	struct pmu_msg msg;

	nvkm_info(&pmu->base.subdev, "processing init msg\n");
	pmu_process_init_msg(pmu, &msg);

	pmu_enable_irq(pmu->base.subdev.device);
}

static int
gm20b_pmu_fini(struct nvkm_subdev *subdev, bool suspend)
{
	struct gm20b_pmu *pmu = gm20b_pmu(subdev);

	cancel_work_sync(&pmu->base.recv.work);

	return 0;
}

static void *
gm20b_pmu_dtor(struct nvkm_subdev *subdev)
{
	return gm20b_pmu(subdev);
}

static int
gm20b_pmu_init(struct nvkm_subdev *subdev)
{
	return 0;
}


static const struct nvkm_subdev_func
gm20b_pmu_funcs = {
	.init = gm20b_pmu_init,
	.fini = gm20b_pmu_fini,
	.dtor = gm20b_pmu_dtor,
	.intr = gm20b_pmu_intr,
};

int
gm20b_pmu_new(struct nvkm_device *device, int index, struct nvkm_pmu **ppmu)
{
	static const struct nvkm_pmu_func func = {};
	struct gm20b_pmu *pmu;

	if (!(pmu = kzalloc(sizeof(*pmu), GFP_KERNEL)))
		return -ENOMEM;

	pmu->base.func = &func;
	*ppmu = &pmu->base;

	nvkm_subdev_ctor(&gm20b_pmu_funcs, device, index, 0, &pmu->base.subdev);

	INIT_WORK(&pmu->base.recv.work, pmu_process_message);

	return 0;
}
