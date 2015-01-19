#ifndef __NVKM_FB_H__
#define __NVKM_FB_H__
#include <core/subdev.h>

#include <subdev/mmu.h>

/* memory type/access flags, do not match hardware values */
#define NV_MEM_ACCESS_RO  1
#define NV_MEM_ACCESS_WO  2
#define NV_MEM_ACCESS_RW (NV_MEM_ACCESS_RO | NV_MEM_ACCESS_WO)
#define NV_MEM_ACCESS_SYS 4
#define NV_MEM_ACCESS_VM  8
#define NV_MEM_ACCESS_NOSNOOP 16

#define NV_MEM_TARGET_VRAM        0
#define NV_MEM_TARGET_PCI         1
#define NV_MEM_TARGET_PCI_NOSNOOP 2
#define NV_MEM_TARGET_VM          3
#define NV_MEM_TARGET_GART        4

#define NV_MEM_TYPE_VM 0x7f
#define NV_MEM_COMP_VM 0x03

/**
 * struct nvkm_mem - allocated memory
 *
 * Physical memory can be provided through 3 different ways:
 * 1) as an array of pages, using the pages member
 * 2) as a SG table, using the sg member
 * 3) as a list of nouveau_mm_node, using the regions member
 *
 * One and only one of these backing mechanisms can be used at a given time.
 * nouveau_vm_map() will use the correct mapping function according to which
 * one is used.
 *
 * @dev: DRM device this memory is allocated for
 * @bar_vma: if this object is mapped into the BAR, this records its mapping
 * @vma: where this object is mapped in the GPU virtual address space. The
 *       second index is used when copying/moving objects
 * @page_shift: size of allocated memory pages
 * @memtype: type of memory
 * @offset: start address of the physical memory backing this object. This
 *          may not be completely meaningful if the memory is not contiguous
 * @size: size of the memory object in pages
 *
 * Only one of the following members can be used at the same time:
 *
 * @regions: list of nouveau_mm_node describing the physical regions of VRAM
 *           allocated to this memory object
 * @pages: array of "size" addresses to the beginning of physical memory
 *         pages backing this memory object
 * @sg: SG table backing this memory object
 */
struct nvkm_mem {
	struct drm_device *dev;

	struct nvkm_vma bar_vma;
	struct nvkm_vma vma[2];
	u8  page_shift;

	struct nvkm_mm_node *tag;
	struct list_head regions;
	dma_addr_t *pages;
	u32 memtype;
	u64 offset;
	u64 size;
	struct sg_table *sg;
};

struct nvkm_fb_tile {
	struct nvkm_mm_node *tag;
	u32 addr;
	u32 limit;
	u32 pitch;
	u32 zcomp;
};

struct nvkm_fb {
	struct nvkm_subdev base;

	bool (*memtype_valid)(struct nvkm_fb *, u32 memtype);

	struct nvkm_ram *ram;

	struct nvkm_mm vram;
	struct nvkm_mm tags;

	struct {
		struct nvkm_fb_tile region[16];
		int regions;
		void (*init)(struct nvkm_fb *, int i, u32 addr, u32 size,
			     u32 pitch, u32 flags, struct nvkm_fb_tile *);
		void (*comp)(struct nvkm_fb *, int i, u32 size, u32 flags,
			     struct nvkm_fb_tile *);
		void (*fini)(struct nvkm_fb *, int i, struct nvkm_fb_tile *);
		void (*prog)(struct nvkm_fb *, int i, struct nvkm_fb_tile *);
	} tile;
};

static inline struct nvkm_fb *
nvkm_fb(void *obj)
{
	/* fbram uses this before device subdev pointer is valid */
	if (nv_iclass(obj, NV_SUBDEV_CLASS) &&
	    nv_subidx(obj) == NVDEV_SUBDEV_FB)
		return obj;

	return (void *)nvkm_subdev(obj, NVDEV_SUBDEV_FB);
}

extern struct nvkm_oclass *nv04_fb_oclass;
extern struct nvkm_oclass *nv10_fb_oclass;
extern struct nvkm_oclass *nv1a_fb_oclass;
extern struct nvkm_oclass *nv20_fb_oclass;
extern struct nvkm_oclass *nv25_fb_oclass;
extern struct nvkm_oclass *nv30_fb_oclass;
extern struct nvkm_oclass *nv35_fb_oclass;
extern struct nvkm_oclass *nv36_fb_oclass;
extern struct nvkm_oclass *nv40_fb_oclass;
extern struct nvkm_oclass *nv41_fb_oclass;
extern struct nvkm_oclass *nv44_fb_oclass;
extern struct nvkm_oclass *nv46_fb_oclass;
extern struct nvkm_oclass *nv47_fb_oclass;
extern struct nvkm_oclass *nv49_fb_oclass;
extern struct nvkm_oclass *nv4e_fb_oclass;
extern struct nvkm_oclass *nv50_fb_oclass;
extern struct nvkm_oclass *g84_fb_oclass;
extern struct nvkm_oclass *gt215_fb_oclass;
extern struct nvkm_oclass *mcp77_fb_oclass;
extern struct nvkm_oclass *mcp89_fb_oclass;
extern struct nvkm_oclass *gf100_fb_oclass;
extern struct nvkm_oclass *gk104_fb_oclass;
extern struct nvkm_oclass *gk20a_fb_oclass;
extern struct nvkm_oclass *gm107_fb_oclass;

#include <subdev/bios.h>
#include <subdev/bios/ramcfg.h>

struct nvkm_ram_data {
	struct list_head head;
	struct nvbios_ramcfg bios;
	u32 freq;
};

struct nvkm_ram {
	struct nvkm_object base;
	enum {
		NV_MEM_TYPE_UNKNOWN = 0,
		NV_MEM_TYPE_STOLEN,
		NV_MEM_TYPE_SGRAM,
		NV_MEM_TYPE_SDRAM,
		NV_MEM_TYPE_DDR1,
		NV_MEM_TYPE_DDR2,
		NV_MEM_TYPE_DDR3,
		NV_MEM_TYPE_GDDR2,
		NV_MEM_TYPE_GDDR3,
		NV_MEM_TYPE_GDDR4,
		NV_MEM_TYPE_GDDR5
	} type;
	u64 stolen;
	u64 size;
	u32 tags;

	int ranks;
	int parts;
	int part_mask;

	int  (*get)(struct nvkm_fb *, u64 size, u32 align, u32 size_nc,
		    u32 type, struct nvkm_mem **);
	void (*put)(struct nvkm_fb *, struct nvkm_mem **);

	int  (*calc)(struct nvkm_fb *, u32 freq);
	int  (*prog)(struct nvkm_fb *);
	void (*tidy)(struct nvkm_fb *);
	u32 freq;
	u32 mr[16];
	u32 mr1_nuts;

	struct nvkm_ram_data *next;
	struct nvkm_ram_data former;
	struct nvkm_ram_data xition;
	struct nvkm_ram_data target;
};
#endif
