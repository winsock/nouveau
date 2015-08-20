/*
 * Copyright 2012 Red Hat Inc.
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
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs
 */
#define nvkm_udevice(p) container_of((p), struct nvkm_udevice, object)
#include "priv.h"

#include <core/client.h>
#include <core/parent.h>
#include <subdev/fb.h>
#include <subdev/instmem.h>
#include <subdev/timer.h>
#include <engine/disp.h>
#include <engine/dmaobj.h>
#include <engine/fifo.h>
#include <engine/pm.h>

#include <nvif/class.h>
#include <nvif/unpack.h>

struct nvkm_udevice {
	struct nvkm_object object;
	struct nvkm_device *device;
};

static int
nvkm_udevice_info(struct nvkm_udevice *udev, void *data, u32 size)
{
	struct nvkm_object *object = &udev->object;
	struct nvkm_device *device = udev->device;
	struct nvkm_fb *fb = device->fb;
	struct nvkm_instmem *imem = device->imem;
	union {
		struct nv_device_info_v0 v0;
	} *args = data;
	int ret;

	nvif_ioctl(object, "device info size %d\n", size);
	if (nvif_unpack(args->v0, 0, 0, false)) {
		nvif_ioctl(object, "device info vers %d\n", args->v0.version);
	} else
		return ret;

	switch (device->chipset) {
	case 0x01a:
	case 0x01f:
	case 0x04c:
	case 0x04e:
	case 0x063:
	case 0x067:
	case 0x068:
	case 0x0aa:
	case 0x0ac:
	case 0x0af:
		args->v0.platform = NV_DEVICE_INFO_V0_IGP;
		break;
	default:
		if (device->pdev) {
			if (pci_find_capability(device->pdev, PCI_CAP_ID_AGP))
				args->v0.platform = NV_DEVICE_INFO_V0_AGP;
			else
			if (pci_is_pcie(device->pdev))
				args->v0.platform = NV_DEVICE_INFO_V0_PCIE;
			else
				args->v0.platform = NV_DEVICE_INFO_V0_PCI;
		} else {
			args->v0.platform = NV_DEVICE_INFO_V0_SOC;
		}
		break;
	}

	switch (device->card_type) {
	case NV_04: args->v0.family = NV_DEVICE_INFO_V0_TNT; break;
	case NV_10:
	case NV_11: args->v0.family = NV_DEVICE_INFO_V0_CELSIUS; break;
	case NV_20: args->v0.family = NV_DEVICE_INFO_V0_KELVIN; break;
	case NV_30: args->v0.family = NV_DEVICE_INFO_V0_RANKINE; break;
	case NV_40: args->v0.family = NV_DEVICE_INFO_V0_CURIE; break;
	case NV_50: args->v0.family = NV_DEVICE_INFO_V0_TESLA; break;
	case NV_C0: args->v0.family = NV_DEVICE_INFO_V0_FERMI; break;
	case NV_E0: args->v0.family = NV_DEVICE_INFO_V0_KEPLER; break;
	case GM100: args->v0.family = NV_DEVICE_INFO_V0_MAXWELL; break;
	default:
		args->v0.family = 0;
		break;
	}

	args->v0.chipset  = device->chipset;
	args->v0.revision = device->chiprev;
	if (fb && fb->ram)
		args->v0.ram_size = args->v0.ram_user = fb->ram->size;
	else
		args->v0.ram_size = args->v0.ram_user = 0;
	if (imem && args->v0.ram_size > 0)
		args->v0.ram_user = args->v0.ram_user - imem->reserved;

	strncpy(args->v0.chip, device->chip->name, sizeof(args->v0.chip));
	strncpy(args->v0.name, device->name, sizeof(args->v0.name));
	return 0;
}

static int
nvkm_udevice_time(struct nvkm_udevice *udev, void *data, u32 size)
{
	struct nvkm_device *device = udev->device;
	struct nvkm_timer *tmr = device->timer;
	union {
		struct nv_device_time_v0 v0;
	} *args = data;
	int ret;

	if (nvif_unpack(args->v0, 0, 0, false)) {
		args->v0.time = tmr->read(tmr);
	}

	return ret;
}

static int
nvkm_udevice_mthd(struct nvkm_object *object, u32 mthd, void *data, u32 size)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	switch (mthd) {
	case NV_DEVICE_V0_INFO:
		return nvkm_udevice_info(udev, data, size);
	case NV_DEVICE_V0_TIME:
		return nvkm_udevice_time(udev, data, size);
	default:
		break;
	}
	return -EINVAL;
}

static int
nvkm_udevice_rd08(struct nvkm_object *object, u64 addr, u8 *data)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	*data = nvkm_rd08(udev->device, addr);
	return 0;
}

static int
nvkm_udevice_rd16(struct nvkm_object *object, u64 addr, u16 *data)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	*data = nvkm_rd16(udev->device, addr);
	return 0;
}

static int
nvkm_udevice_rd32(struct nvkm_object *object, u64 addr, u32 *data)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	*data = nvkm_rd32(udev->device, addr);
	return 0;
}

static int
nvkm_udevice_wr08(struct nvkm_object *object, u64 addr, u8 data)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	nvkm_wr08(udev->device, addr, data);
	return 0;
}

static int
nvkm_udevice_wr16(struct nvkm_object *object, u64 addr, u16 data)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	nvkm_wr16(udev->device, addr, data);
	return 0;
}

static int
nvkm_udevice_wr32(struct nvkm_object *object, u64 addr, u32 data)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	nvkm_wr32(udev->device, addr, data);
	return 0;
}

static int
nvkm_udevice_map(struct nvkm_object *object, u64 *addr, u32 *size)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	struct nvkm_device *device = udev->device;
	*addr = nv_device_resource_start(device, 0);
	*size = nv_device_resource_len(device, 0);
	return 0;
}

static int
nvkm_udevice_fini(struct nvkm_object *object, bool suspend)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	struct nvkm_device *device = udev->device;
	int ret = 0;

	mutex_lock(&device->mutex);
	if (!--device->refcount) {
		ret = nvkm_device_fini(device, suspend);
		if (ret && suspend) {
			device->refcount++;
			goto done;
		}
	}

done:
	mutex_unlock(&device->mutex);
	return ret;
}

static int
nvkm_udevice_init(struct nvkm_object *object)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	struct nvkm_device *device = udev->device;
	int ret = 0;

	mutex_lock(&device->mutex);
	if (!device->refcount++) {
		ret = nvkm_device_init(device);
		if (ret) {
			device->refcount--;
			goto done;
		}
	}

done:
	mutex_unlock(&device->mutex);
	return ret;
}

static int
nvkm_udevice_child_old(const struct nvkm_oclass *oclass,
		       void *data, u32 size, struct nvkm_object **pobject)
{
	struct nvkm_object *parent = oclass->parent;
	struct nvkm_engine *engine = oclass->engine;
	struct nvkm_oclass *eclass = (void *)oclass->priv;
	struct nvkm_object *engctx = NULL;
	int ret;

	if (engine->cclass) {
		ret = nvkm_object_old(parent, &engine->subdev.object,
				      engine->cclass, NULL, 0, &engctx);
		if (ret)
			return ret;
	} else {
		nvkm_object_ref(parent, &engctx);
	}

	ret = nvkm_object_old(engctx, &engine->subdev.object, eclass,
			      data, size, pobject);
	nvkm_object_ref(NULL, &engctx);
	return ret;
}

static int
nvkm_udevice_child_new(const struct nvkm_oclass *oclass,
		       void *data, u32 size, struct nvkm_object **pobject)
{
	struct nvkm_udevice *udev = nvkm_udevice(oclass->parent);
	const struct nvkm_oclass *sclass = oclass->priv;
	return nvkm_object_old(&udev->object, NULL,
			       (struct nvkm_oclass *)sclass,
			       data, size, pobject);
}

static int
nvkm_udevice_child_get(struct nvkm_object *object, int index,
		       struct nvkm_oclass *oclass)
{
	struct nvkm_udevice *udev = nvkm_udevice(object);
	struct nvkm_device *device = udev->device;
	struct nvkm_engine *engine;
	u64 mask = (1ULL << NVDEV_ENGINE_DMAOBJ) |
		   (1ULL << NVDEV_ENGINE_FIFO) |
		   (1ULL << NVDEV_ENGINE_DISP) |
		   (1ULL << NVDEV_ENGINE_PM);
	int i;

	for (; i = __ffs64(mask), mask; mask &= ~(1ULL << i)) {
		if ((engine = nvkm_device_engine(device, i))) {
			struct nvkm_oclass *sclass = engine->sclass;
			int c = 0;
			while (sclass && sclass->ofuncs) {
				if (c++ == index) {
					oclass->base.oclass = sclass->handle;
					oclass->base.minver = -2;
					oclass->base.maxver = -2;
					oclass->ctor = nvkm_udevice_child_old;
					oclass->priv = sclass;
					oclass->engine = engine;
					return 0;
				}
				sclass++;
			}
			index -= c;
		}
	}

	if (index == 0) {
		oclass->ctor = nvkm_udevice_child_new;
		oclass->base.oclass = nvkm_control_oclass[0].handle;
		oclass->base.minver = -2;
		oclass->base.maxver = -2;
		oclass->priv = &nvkm_control_oclass[0];
		return 0;
	}

	return -EINVAL;
}

static const struct nvkm_object_func
nvkm_udevice_super = {
	.init = nvkm_udevice_init,
	.fini = nvkm_udevice_fini,
	.mthd = nvkm_udevice_mthd,
	.map = nvkm_udevice_map,
	.rd08 = nvkm_udevice_rd08,
	.rd16 = nvkm_udevice_rd16,
	.rd32 = nvkm_udevice_rd32,
	.wr08 = nvkm_udevice_wr08,
	.wr16 = nvkm_udevice_wr16,
	.wr32 = nvkm_udevice_wr32,
	.sclass = nvkm_udevice_child_get,
};

static const struct nvkm_object_func
nvkm_udevice = {
	.init = nvkm_udevice_init,
	.fini = nvkm_udevice_fini,
	.mthd = nvkm_udevice_mthd,
	.sclass = nvkm_udevice_child_get,
};

int
nvkm_udevice_new(const struct nvkm_oclass *oclass, void *data, u32 size,
		 struct nvkm_object **pobject)
{
	union {
		struct nv_device_v0 v0;
	} *args = data;
	struct nvkm_client *client = oclass->client;
	struct nvkm_object *parent = &client->object;
	const struct nvkm_object_func *func;
	struct nvkm_udevice *udev;
	int ret;

	nvif_ioctl(parent, "create device size %d\n", size);
	if (nvif_unpack(args->v0, 0, 0, false)) {
		nvif_ioctl(parent, "create device v%d device %016llx\n",
			   args->v0.version, args->v0.device);
	} else
		return ret;

	/* give priviledged clients register access */
	if (client->super)
		func = &nvkm_udevice_super;
	else
		func = &nvkm_udevice;

	if (!(udev = kzalloc(sizeof(*udev), GFP_KERNEL)))
		return -ENOMEM;
	nvkm_object_ctor(func, oclass, &udev->object);
	*pobject = &udev->object;

	/* find the device that matches what the client requested */
	if (args->v0.device != ~0)
		udev->device = nvkm_device_find(args->v0.device);
	else
		udev->device = nvkm_device_find(client->device);
	if (!udev->device)
		return -ENODEV;

	return 0;
}

const struct nvkm_sclass
nvkm_udevice_sclass = {
	.oclass = NV_DEVICE,
	.minver = 0,
	.maxver = 0,
	.ctor = nvkm_udevice_new,
};
