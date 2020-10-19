/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
	/* Team name */
	"MiSau",
	/* First member's full name */
	"Mitul Tyagi",
	/* First member's email address */
	"mitulty@ee.iitb.ac.in",
	/* Second member's full name (leave blank if none) */
	"Tarun Saurabh",
	/* Second member's email address (leave blank if none) */
	"member_2@cse.iitb.ac.in"
	};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define METADATA_SIZE (ALIGN(sizeof(struct metadata_block)))

struct metadata_block
{
	size_t size;
	int flag; // 0 is free and 1 is occupied
	struct metadata_block *next_chunk;
    struct metadata_block *prev_chunk;

};

struct metadata_block *start_free_head = NULL;
void * root=NULL;
struct metadata_block *start_tail = NULL;
void *init_mem_sbrk_break = NULL;
/* 
 * mm_init - initialize the malloc package.
 */

struct metadata_block *get_free_block(struct metadata_block **last, size_t size);
void coalesce(struct metadata_block *node);
void show_list_up(void);
void show_list_down(void);
struct metadata_block *alloc_space(struct metadata_block *last, size_t size);

int mm_init(void)
{

	//This function is called every time before each test run of the trace.
	//It should reset the entire state of your malloc or the consecutive trace runs will give wrong answer.
	//printf("Reached Init................................................................................................\n");
	init_mem_sbrk_break = NULL;
	start_free_head = NULL;
	start_tail = NULL;
	/* 
	 * This function should initialize and reset any data structures used to represent the starting state(empty heap)
	 * 
	 * This function will be called multiple times in the driver code "mdriver.c"
	 */

	return 0; //Returns 0 on successfull initialization.
}

//---------------------------------------------------------------------------------------------------------------
/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
	/* 
	 * This function should keep track of the allocated memory blocks.
	 * The block allocation should minimize the number of holes (chucks of unusable memory) in the heap memory.
	 * The previously freed memory blocks should be reused.
	 * If no appropriate free block is available then the increase the heap  size using 'mem_sbrk(size)'.
	 * Try to keep the heap size as small as possible.
	 */
	// printf("Called Malloc of size %d\n", size);
	// printf("Before Malloc Call..........................................................................\n");
	// show_list_up();
	// show_list_down();
	if (size <= 0)
	{ // Invalid request size
		return NULL;
	}
	size = ((size + 7) / 8) * 8; //size alligned to 8 bytes
	struct metadata_block *chunk;
	if (!root)
	{
		chunk = alloc_space(NULL, size);
		if (!chunk)
			return NULL;
		root =(struct metadata_block*) chunk;
	}
	else
	{
		struct metadata_block *last = start_head;
		chunk = get_free_block(&last, size);
		if (!chunk)
		{
			chunk = alloc_space(last, size);
			if (!chunk)
			{
				return NULL;
			}
		}
	}
	// printf("After Malloc Call..........................................................................\n");
	// show_list_up();
	// show_list_down();
	// printf("Returned from Malloc\n");
	//printf("chunk=%p,chunk+metadata=%p, size=%d and metadata+size=%d\n",chunk,(char*)chunk+METADATA_SIZE,size,METADATA_SIZE+size);
	return ((char *)chunk + METADATA_SIZE);
	//return mem_sbrk(size);
	//mem_sbrk() is wrapper function for the sbrk() system call.
	//Please use mem_sbrk() instead of sbrk() otherwise the evaluation results
	//may give wrong results
}

void mm_free(void *ptr)
{
	/* 
	 * Searches the previously allocated node for memory block with base address ptr.
	 * 
	 * It should also perform coalesceing on both ends i.e. if the consecutive memory blocks are 
	 * free(not allocated) then they should be combined into a single block.
	 * 
	 * It should also keep track of all the free memory blocks.
	 * If the freed block is at the end of the heap then you can also decrease the heap size 
	 * using 'mem_sbrk(-size)'.
	 */
	//printf("Called Free\n");
	if (!ptr)
	{
		return;
	}
	int f = 0;
	struct metadata_block *header = start_head, *footer = NULL;
	while (header != NULL)
	{
		if (((char *)header + METADATA_SIZE) == ptr)
		{
			f = 1;
			break;
		}

		header = header->next_chunk;
	}
	if (f == 1)
	{
		assert(header->flag != 0);
		header->flag = 0;
		footer = (struct metadata_block *)((char *)header + header->size + METADATA_SIZE);
		footer->flag = 0;
		coalesce(header);
	}
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
	size = ((size + 7) / 8) * 8; //8-byte alignement
//	printf("Called Realloc\n");

	if (ptr == NULL)
	{ //memory was not previously allocated
		return mm_malloc(size);
	}

	if (size == 0)
	{ //new size is zero
		mm_free(ptr);
		return NULL;
	}

	/*
	 * This function should also copy the content of the previous memory block into the new block.
	 * You can use 'memcpy()' for this purpose.
	 * 
	 * The data structures corresponding to free memory blocks and allocated memory 
	 * blocks should also be updated.
	*/
	struct metadata_block *pr_block = start_head;
	while (((char *)pr_block + METADATA_SIZE) != ptr)
	{
		pr_block = pr_block->next_chunk;
		if(!pr_block)
			return NULL;
	}
	if (pr_block->size >= size)
	{
		return ptr;
	}
	void *nptr;
	nptr = mm_malloc(size);
	if (!nptr)
	{
		return NULL;
	}
	memcpy(nptr, ptr, pr_block->size);
	mm_free(ptr);
	return (nptr);
}

struct metadata_block *alloc_space(struct metadata_block *last, size_t size)
{
	struct metadata_block *header, *footer;
	header = mem_sbrk(0);
	void *request = mem_sbrk(METADATA_SIZE + size);
	footer = mem_sbrk(METADATA_SIZE);
	//init_mem_sbrk_break = 2 * METADATA_SIZE + size;
	assert((void *)header == request);
	if (request == (void *)-1)
	{
		return NULL;
	}
    if(!last)
    {
        header=
    }
	return header;
}
struct metadata_block *get_free_block(struct metadata_block **last, size_t size) //Best Fit
{
	struct metadata_block *pr_block = start_head, *min_block_header = NULL, *min_block_footer = NULL;
	int min_size = 1000000,max_size=0, x;
	size_t size_needed_withsplitting = size + 2 * METADATA_SIZE;
	size_t size_needed_withoutsplitting=size;

	while (pr_block != NULL)
	{
		if (pr_block->size >= size_needed_withoutsplitting && pr_block->size <= min_size && pr_block->flag == 0)//Best Fit
	    //if (pr_block->size >= size_needed && pr_block->flag == 0)//First Fit
		//if (pr_block->size >= size_needed && pr_block->size >= max_size && pr_block->flag == 0)//Worst Fit
		{
			min_block_header = pr_block;
			min_size = pr_block->size;//Best Fit
		//	max_size=pr_block->size; // Worst Fit
		//	break;//First Fit
		}
		*last = pr_block;
		pr_block = pr_block->next_chunk;
	}

	//	Splitting
	// if (min_block_header != NULL)
	// {
		// 
		// min_block_footer = (struct metadata_block *)((char *)min_block_header + min_block_header->size + METADATA_SIZE);
		// x = min_block_header->size - (2 * METADATA_SIZE+size);
		// min_block_header->size = size;
		// min_block_header->flag = 1;
		// struct metadata_block *pr_bl_footer = (struct metadata_block *)((char *)min_block_header + size + METADATA_SIZE);
		// struct metadata_block *new_bl_header = (struct metadata_block *)((char *)min_block_header + size + (2 * METADATA_SIZE));
		// new_bl_header->next_chunk = min_block_header->next_chunk;
		// min_block_header->next_chunk = new_bl_header;
		// pr_bl_footer->next_chunk = min_block_footer->next_chunk;
		// min_block_footer->next_chunk = pr_bl_footer;
		// new_bl_header->size = x;
		// new_bl_header->flag = 0;
		// min_block_footer->flag = 0;
		// min_block_footer->size = x;
		// pr_bl_footer->flag = 1;
		// pr_bl_footer->size = size;		
	// }

	//No Splitting
	if(min_block_header!=NULL)
	{			
		min_block_footer = (struct metadata_block *)((char *)min_block_header + min_block_header->size + METADATA_SIZE);
		min_block_footer->flag=1;
		min_block_header->flag=1;
	}

	return min_block_header;
}

void coalesce(struct metadata_block *header)
{

	struct metadata_block *next_node_header = NULL, *next_node_footer = NULL, *previous_node_header = NULL, *previous_node_footer = NULL, *footer = NULL;
	footer = (struct metadata_block *)((char *)header + header->size + METADATA_SIZE);
	//printf("Coalescing at header and footer: %p %p\n",header,footer);
	if (footer != start_tail)
		next_node_header = header->next_chunk;
	if (header != start_head)
		previous_node_footer = footer->next_chunk;
	if (!header)
		return;
	// printf("------------------------------------------------------Before Coalescing------------------------------------------------\n");
	// show_list_up();
	// show_list_down();
	if (next_node_header != NULL)
	{
		if (next_node_header->flag == 0)
		{
			//printf("Entered Next Node when next node header is %p\n",next_node_header);
			next_node_footer = (struct metadata_block *)((char *)next_node_header + next_node_header->size + METADATA_SIZE);
			header->size += (2 * METADATA_SIZE) + next_node_header->size;
			next_node_footer->size += (2 * METADATA_SIZE) + footer->size;
			header->next_chunk = next_node_header->next_chunk;
			next_node_footer->next_chunk = footer->next_chunk;
			footer = next_node_footer;
		}
	}
	if (previous_node_footer != NULL)
	{
		if (previous_node_footer->flag == 0)
		{
			//	printf("Entered Previous Node when prev. node footer is %p\n",previous_node_footer);
			previous_node_header = (struct metadata_block *)((char *)previous_node_footer - METADATA_SIZE - previous_node_footer->size);
			footer->size += (2 * METADATA_SIZE) + previous_node_footer->size;
			previous_node_header->size += (2 * METADATA_SIZE) + header->size;
			previous_node_header->next_chunk = header->next_chunk;
			footer->next_chunk = previous_node_footer->next_chunk;
		}
	}
	//  printf("-------------------------------------------------------After Coalescing---------------------------------------------------\n");
	//  show_list_up();
	//  show_list_down();
}

void show_list_up(void)
{
	printf("...................................******************************..........................................\n");
	struct metadata_block *pr_block = start_head;
	int i = 0;
	while (pr_block != NULL)
	{
		printf("Reached at chunk from head:%p,pr_block->size:%d,pr_block->flag:%d and index:%d\n", pr_block, pr_block->size, pr_block->flag, i);
		i++;
		pr_block = pr_block->next_chunk;
	}
	printf("....................................*******************************............................................\n");
}

void show_list_down(void)
{
	printf("...................................******************************..........................................\n");
	struct metadata_block *pr_block = start_tail;
	int i = 0;
	while (pr_block != NULL)
	{
		printf("Reached at chunk from tail:%p,pr_block->size:%d,pr_block->flag:%d and index:%d\n", pr_block, pr_block->size, pr_block->flag, i);
		i++;
		pr_block = pr_block->next_chunk;
	}
	printf("....................................*******************************............................................\n");
}