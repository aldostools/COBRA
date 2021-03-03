#include <malloc.h>
#include <lv2/memory.h>

void *kalloc(size_t size)
{
	return alloc(size, 0x2F);
}

void kfree(void *ptr)
{
	dealloc(ptr, 0x2F);
}

void *malloc(size_t size)
{
	return alloc(size, 0x27);
}

void free(void *ptr)
{
	dealloc(ptr, 0x27);
}

int free_page(process_t process, void *page_addr)
{
	return page_free(process, page_addr, 0x2F);
}

int page_allocate_auto(process_t process, uint64_t size, void **page_addr)
{
	uint64_t page_size;

	if (size >= 0x100000)
	{
		size = (size+0xFFFFF) & ~0xFFFFF;
		page_size = MEMORY_PAGE_SIZE_1M;
	}
	else if (size >= 0x10000)
	{
		size = (size+0xFFFF) & ~0xFFFF;
		page_size = MEMORY_PAGE_SIZE_64K;
	}
	else
	{
		if (size > 0x1000)
			size = (size+0xFFF) & ~0xFFF;
		else
			size = 0x1000;

		page_size = MEMORY_PAGE_SIZE_4K;
	}

	uint64_t flags = 0x2F;
	return page_allocate(process, size, flags, page_size, page_addr);
}
