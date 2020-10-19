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
	"member_2@cse.iitb.ac.in"};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define METADATA_SIZE (ALIGN(sizeof(struct metadata_block)))
#define FREE_BLOCK_SIZE (ALIGN(sizeof(struct free_block)))
struct metadata_block
{
	size_t size;
	struct metadata_block *next_chunk;
};

struct free_block
{
	int size;
	int height;
	struct free_block *left;
	struct free_block *right;
};

struct metadata_block *start_head = NULL;
struct metadata_block *start_tail = NULL;
struct free_block *free_list_root = NULL, *parent = NULL, *temp_parent = NULL;
void *init_mem_sbrk_break = NULL;
int found = 0, flag = 0;
struct metadata_block *get_free_block(struct metadata_block **last, size_t size);
struct metadata_block *coalesce(struct metadata_block *node);
void show_list_up(void);
void show_list_down(void);
void findNode_InOrder(struct free_block *root, int size, struct free_block **node);
struct free_block *delete_coalescing(struct free_block *root, int size, struct free_block *address);
void add(struct metadata_block *header);
int height(struct free_block *N);
int max(int a, int b);
void preOrder(struct free_block *root);
void inOrder(struct free_block *root);
struct free_block *rightRotate(struct free_block *y);
struct free_block *leftRotate(struct free_block *x);
int getBalance(struct free_block *N);
struct free_block *minValueNode(struct free_block *node);
struct free_block *deleteNode(struct free_block *root, int size, struct free_block *address);
void findNode(struct free_block *root, int size, struct free_block **node);
struct free_block *insert(struct free_block *root, struct free_block *node, int size);
struct metadata_block *alloc_space(struct metadata_block *last, size_t size);
struct free_block *search(struct free_block *root, int key, struct free_block *node);
void parentNode(struct free_block *root, struct free_block *node, int size, struct free_block **parent);

/* 
 * mm_init - initialize the malloc package.
 */

int mm_init(void)
{

	//This function is called every time before each test run of the trace.
	//It should reset the entire state of your malloc or the consecutive trace runs will give wrong answer.
	//printf("Reached Init................................................................................................\n");
	init_mem_sbrk_break = NULL;
	start_head = NULL;
	free_list_root = NULL;
	start_tail = NULL;
	parent = NULL;
	found = 0;
	flag = 0;
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

//	printf("Called Malloc for size %d\n", size);

	// show_list_up();
	// show_list_down();
	if (size <= 0)
	{ // Invalid request size
		return NULL;
	}
	size = ((size + 7) / 8) * 8; //size alligned to 8 bytes
	struct metadata_block *chunk = NULL, *chunk_footer = NULL;
	struct free_block *found_node = NULL;

	if (!start_head)
	{
		chunk = alloc_space(NULL, size);
		if (!chunk)
			return NULL;
		start_head = chunk;
	}
	else
	{
		struct metadata_block *last = start_head;
		found = 0;
	//	printf("Finding Node\n");
		findNode_InOrder(free_list_root, size, &found_node); // Finding the block
		if (!found_node || found_node->size < size)
		{
	//		printf("No Node Found\n");
			while (last->next_chunk != NULL)
				last = last->next_chunk;
			chunk = alloc_space(last, size);
			if (!chunk)
			{
				return NULL;
			}
		}
		else
		{
	//		printf("Found The Node: %p With Size %d\n", found_node, found_node->size);
			chunk = (struct metadata_block *)((char *)found_node - METADATA_SIZE);
			chunk_footer = (struct metadata_block *)((char *)chunk + chunk->size + METADATA_SIZE);
			chunk->size |= 1;
			chunk_footer->size |= 1;
			parent = free_list_root;
			flag=0;
			delete_coalescing(free_list_root, found_node->size, found_node);
			found_node->size |= 1;
		}
	}
	// printf("After Malloc Call of Size %d..........................................................................\n", size);
	// printf("...................................***********AFTER MALLOC*******************..........................................\n");
	// inOrder(free_list_root);
	// printf("\n--**----\n");
	// preOrder(free_list_root);
	// printf("\n.................................***********AFTER MALLOC*******************..........................................\n");

	//	show_list_up();
	//show_list_down();
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
	if (!ptr)
	{
		return;
	}
	int f = 0;
	struct metadata_block *header = start_head, *footer = NULL, *header_new = NULL;
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
//	printf("Called Free For header %p of size %d and pointer %p\n", header, header->size & ~1, (struct free_block *)((char *)header + METADATA_SIZE));
		assert((header->size & 1) % 2 != 0);
		header->size &= ~1;
		footer = (struct metadata_block *)((char *)header + header->size + METADATA_SIZE);
		footer->size &= ~1;
		header_new = coalesce(header);
		add(header_new);
		//show_list_up();
		// printf("...................................***********AFTER INSERTION*******************..........................................\n");
		// inOrder(free_list_root);
		// printf("\n------\n");
		// preOrder(free_list_root);
		// printf("\n.................................***********AFTER INSERTION*******************..........................................\n");
	}
	return;
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
	size = ((size + 7) / 8) * 8; //8-byte alignement
	//printf("Called Realloc\n");

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
		if (!pr_block)
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
	memcpy(nptr, ptr, (pr_block->size & ~1));
	mm_free(ptr);
	return (nptr);
}

struct metadata_block *alloc_space(struct metadata_block *last, size_t size)
{
	struct metadata_block *header, *footer;
	header = mem_sbrk(0);
	if (size < FREE_BLOCK_SIZE)
		size = FREE_BLOCK_SIZE;
	void *request = mem_sbrk(METADATA_SIZE + size);
	footer = mem_sbrk(METADATA_SIZE);
	//	init_mem_sbrk_break = 2 * METADATA_SIZE + size;
	assert((void *)header == request);
	if (request == (void *)-1)
	{
		return NULL;
	}
	if (last)
	{
		last->next_chunk = header;
		footer->next_chunk = start_tail;
		start_tail = footer;
	}
	if (!last)
	{
		footer->next_chunk = NULL;
		start_tail = footer;
	}
	header->size = size | 1;
	header->next_chunk = NULL;
	footer->size = size | 1;
	return header;
}

struct metadata_block *coalesce(struct metadata_block *header)
{

	struct metadata_block *next_node_header = NULL, *next_node_footer = NULL, *previous_node_header = NULL, *previous_node_footer = NULL, *footer = NULL;
	footer = (struct metadata_block *)((char *)header + header->size + METADATA_SIZE);
	struct free_block *address = NULL;
	parent = free_list_root;

	//printf("Coalescing at header and footer: %p %p\n",header,footer);
	if (footer != start_tail)
		next_node_header = header->next_chunk;
	if (header != start_head)
		previous_node_footer = footer->next_chunk;
	if (!header)
		return NULL;
	if (next_node_header != NULL)
	{
		if ((next_node_header->size & 1) % 2 == 0)
		{
			address = (struct free_block *)((char *)next_node_header + METADATA_SIZE);
	//		printf("Coalescing Next Node %d/%d when root is %p and coalesced node is %p\n", address->size, next_node_header->size, free_list_root, address);
			parent = free_list_root;
			flag = 0;
			delete_coalescing(free_list_root, next_node_header->size, address);
	//		printf("\nReturned From Deleting in Coalescing Next Node\n");
			next_node_footer = (struct metadata_block *)((char *)next_node_header + next_node_header->size + METADATA_SIZE);
			header->size += (2 * METADATA_SIZE) + next_node_header->size;
			next_node_footer->size += (2 * METADATA_SIZE) + footer->size;
			header->next_chunk = next_node_header->next_chunk;
			next_node_footer->next_chunk = footer->next_chunk;
			footer = next_node_footer;
		}
	}
	// printf("\n...................................***********AFTER NEXT COALESCING*******************..........................................\n");
	// inOrder(free_list_root);
	// printf("\n------\n");
	// preOrder(free_list_root);
	// printf("\n..................................***********AFTER NEXT COALESCING*******************..........................................\n");
// 
	if (previous_node_footer != NULL)
	{
		if ((previous_node_footer->size & 1) % 2 == 0)
		{
			previous_node_header = (struct metadata_block *)((char *)previous_node_footer - (METADATA_SIZE + previous_node_footer->size));
			address = (struct free_block *)((char *)previous_node_header + METADATA_SIZE);
	//		printf("Coalescing Prev Node %d/%d when root is %p and coalesced node is %p\n", previous_node_header->size, address->size, free_list_root, address);
			parent = free_list_root;
			flag = 0;
			delete_coalescing(free_list_root, previous_node_header->size, address);
	//		printf("\nReturned From Deleting in Coalescing Previous Node\n");
			footer->size += (2 * METADATA_SIZE) + previous_node_footer->size;
			previous_node_header->size += (2 * METADATA_SIZE) + header->size;
			previous_node_header->next_chunk = header->next_chunk;
			footer->next_chunk = previous_node_footer->next_chunk;
			header = previous_node_header;
		}
	}
//	printf("Done Coalescing and total size to be inserted %d\n", header->size);
	return header;
}

void show_list_up(void)
{
	printf("...................................******************************..........................................\n");
	struct metadata_block *pr_block = start_head;
	struct free_block *address = NULL;

	int i = 0;
	while (pr_block != NULL)
	{
		address = (struct free_block *)((char *)pr_block + METADATA_SIZE);
		if ((pr_block->size % 2) == 0)
			printf("{{Reached at chunk:%p,pr_block->size:%d, free_list_pointer: %p}}\n", pr_block, pr_block->size, address);

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
		printf("Reached at chunk:%p,pr_block->size:%d,pr_block->flag:%d and index:%d\n", pr_block, pr_block->size, pr_block->size & 1, i);
		i++;
		pr_block = pr_block->next_chunk;
	}
	printf("....................................*******************************............................................\n");
}

/* 
 * mm_init - initialize the malloc package.
 */

struct free_block *insert(struct free_block *root, struct free_block *node, int size)
{
	if (root == NULL)
	{
		return (node);
	}
	//printf("Entering Insertion of Node When Root is %p(%d) and node is %p(%d) %d\n", root, root->size, node, node->size, size);
	if (size < root->size)
	{
		//		printf("Entering Left\n");
		root->left = insert(root->left, node, size);
	}
	else if (size >= root->size)
	{
		//		printf("Entering Right\n");
		root->right = insert(root->right, node, size);
	}
	else
		return root;
	root->height = 1 + max(height(root->left), height(root->right));
	int balance = getBalance(root);
	if (balance > 1 && size < root->left->size) // RR
	{

		return rightRotate(root);
	}
	if (balance < -1 && size >= root->right->size) //LL
	{
		return leftRotate(root);
	}
	if (balance > 1 && size >= root->left->size) //LR
	{
		root->left = leftRotate(root->left);
		return rightRotate(root);
	}
	if (balance < -1 && size < root->right->size)
	{
		root->right = rightRotate(root->right);
		return leftRotate(root);
	}
	return root;
}

int height(struct free_block *N)
{
	if (N == NULL)
		return 0;
	return N->height;
}
int max(int a, int b)
{
	return (a > b) ? a : b;
}

struct free_block *rightRotate(struct free_block *y)
{
	struct free_block *x = y->left;
	struct free_block *T2 = x->right;
	x->right = y;
	y->left = T2;
	y->height = max(height(y->left), height(y->right)) + 1;
	x->height = max(height(x->left), height(x->right)) + 1;
	return x;
}

struct free_block *leftRotate(struct free_block *x)
{
	struct free_block *y = x->right;
	struct free_block *T2 = y->left;
	y->left = x;
	x->right = T2;
	x->height = max(height(x->left), height(x->right)) + 1;
	y->height = max(height(y->left), height(y->right)) + 1;
	return y;
}
int getBalance(struct free_block *N)
{
	if (N == NULL)
		return 0;
	return height(N->left) - height(N->right);
}
struct free_block *minValueNode(struct free_block *node)
{
	struct free_block *current = node;
	while (current->left != NULL)
	{
//		printf("Entering Left with node as %p\n", current);
		temp_parent = current;
		current = current->left;
	}
	return current;
}

void preOrder(struct free_block *root)
{
	if (root != NULL)
	{
		int balance = getBalance(root);
		if (root == free_list_root)
			printf(" {{{-->{%d,%p,%d}<--}}} ", root->size, root,balance);
		else
			printf("  {{%d,%p,%d}} ", root->size, root,balance);
		preOrder(root->left);
		preOrder(root->right);
	}
}

void inOrder(struct free_block *root)
{
	//printf(" Reached: %p when %p\n",root,free_list_root);
	if (root != NULL)
	{
		inOrder(root->left);
				int balance = getBalance(root);
		if (root == free_list_root)
			printf(" {{{-->{%d,%p,%d}<--}}} ", root->size, root,balance);
		else
			printf("  {{%d,%p,%d}} ", root->size, root,balance);
		inOrder(root->right);
	}
}

struct free_block *deleteNode(struct free_block *root, int size, struct free_block *address)
{
	if (root == NULL)
	{
//		printf("Returning \n");
		return root;
	}
//	printf("Entering deleteNode with node %p  deleting->size=%d, and root %p of size=%d\n", address, address->size, root, root->size);
	if (address != root)
	{
		if (address->size < root->size)
		{
//			printf("Left Enter\n");
			parent = root;
//			deleteNode(root->left, size, address);
		}
		else if (address->size >= root->size)
		{
//			printf("Right Enter\n");
			parent = root;
			deleteNode(root->right, size, address);
		}
	}
	else
	{
	//	printf("Found Exact Node  %p with size %d and children as %p %p \n", root, root->size, root->left, root->right);
		if ((root->left == NULL) && (root->right == NULL))
		{
			if (root == free_list_root)
			{
				free_list_root = NULL;
			}
			else
			{
	//			printf("No Child and it's  parent is %p (with children as %p/%p)when root is %p\n", parent, parent->left, parent->right, root);
				if (parent->left == root)
					parent->left = NULL;
				else
					parent->right = NULL;
			}
		}
		else if ((root->left == NULL) || (root->right == NULL)) //Single Child
		{

	//		printf("Single Child with parent %p (it's children as %p/%p)for root as %p\n", parent, parent->left, parent->right, root);
			if (parent == root)
			{
				if (parent->left != NULL)
				{
					free_list_root = parent->left;
					parent->left = NULL;
				}
				else
				{
					free_list_root = parent->right;
					parent->right = NULL;
				}
			}
			else if (parent->left == root)
			{
				if (root->left != NULL)
					parent->left = root->left;
				else
					parent->left = root->right;
			}
			else
			{
				if (root->left != NULL)

					parent->right = root->left;
				else
					parent->right = root->right;
			}
			root->left = NULL;
			root->right = NULL;
		}
		else
		{
			temp_parent = root;
			struct free_block *temp = minValueNode(root->right);
			//printf("Found Replacement %p\n", temp);
			// printf("Two Children for TEMP(%p)  are :left %p and right %p and temp_parent is %p where parent is %p and root is %p\n", temp, temp->left, temp->left, temp_parent, parent, root);
			// printf("Found Dad of %p is %p\n", temp, parent);
			if (parent == root)
			{
				if (temp_parent == parent)
				{
					temp->left = root->left;
					root->left = NULL;
					root->right = NULL;
					free_list_root = temp;
				}
				else
				{
					temp->left = root->left;
					temp_parent->left = temp->right;
					temp->right = root->right;
					root->left = NULL;
					root->right = NULL;
					free_list_root = temp;
				}
			}
			else if (temp_parent == root)
			{
				if (parent->right == root)
					parent->right = temp;
				else
					parent->left = temp;
				temp->left = root->left;
				root->left = NULL;
				root->right = NULL;
			}
			else
			{
				if (parent->right == root)
					parent->right = temp;
				else
					parent->left = temp;
				temp_parent->left = temp->right;
				temp->right = root->right;
				temp->left = root->left;
				root->left = NULL;
				root->right = NULL;
			}
			//	printf("\nGlobal Root node is %p(%p/%p)when node is %p\n", free_list_root, free_list_root->left, free_list_root->right, root);
			return NULL;
		}

	}
	//	printf("\nGlobal Root node is %p whent node is %p\n", free_list_root, root);
	if (root == NULL)
	{
		return NULL;
	}
	root->height = 1 + max(height(root->left), height(root->right));

	int balance = getBalance(root);
	if (balance > 1 && getBalance(root->left) > 0)
		return rightRotate(root);
	if (balance > 1 && getBalance(root->left) < 0)
	{
		root->left = leftRotate(root->left);
		return rightRotate(root);
	}
	if (balance < -1 && getBalance(root->right) < 0)
		return leftRotate(root);
	if (balance < -1 && getBalance(root->right) > 0)
	{
		root->right = rightRotate(root->right);
		return leftRotate(root);
	}
	return NULL;
}

void add(struct metadata_block *header)
{

	struct free_block *node = (struct free_block *)((char *)header + METADATA_SIZE);
	if (!free_list_root)
	{
		free_list_root = node;
		free_list_root->left = NULL;
		free_list_root->right = NULL;
		free_list_root->height = 1;
		free_list_root->size = header->size & ~1;
	}
	else
	{
		node->left = NULL;
		node->right = NULL;
		node->height = 1;
		node->size = header->size & ~1;
		free_list_root = insert(free_list_root, node, header->size);
	}
}
void findNode_InOrder(struct free_block *root, int size, struct free_block **node)
{
		if (root != NULL && found==0)
	{
		findNode_InOrder(root->left,size,node);
		if(size<=root->size)
		{
			found=1;
			*node=root;

		}

		findNode_InOrder(root->right,size, node);
	}
}
void findNode(struct free_block *root, int size, struct free_block **node)
{

	if (root == NULL)
	{
		return;
	}
//	printf("Finding the best fit. Node Reached is %p(%d)\n",root,root->size);
	if (root->left == NULL && root->right == NULL && root == free_list_root)
	{
		if (root->size < size)
		{
			*node = NULL;
			return;
		}
		else
		{
			*node = root;
			return;
		}
	}
	if (root->left == NULL && root->right == NULL)
	{
//		printf("Reached Leaf Node\n");
		if (root->size < size)
		{
			found = 1;
			return;
		}
		else
		{
			*node = root;
			found = 1;
			return;
		}
	}
	if (size < root->size)
	{
		*node = root;
//		printf("Entering Left\n");
		findNode(root->left, size, node);
	}
	else if (size > root->size)
	{
		*node = root;
//		printf("Entering Right\n");
		findNode(root->right, size, node);
	}
	else
	{
		*node = root;
		found = 1;
		return;
	}
	if (found == 0)
	{
		found = 1;
		if (root->size < size)
			*node = NULL;
	}
	return;
}

struct free_block *delete_coalescing(struct free_block *root, int size, struct free_block *address)
{
	if (root == NULL)
	{
	//	printf("Returning \n");
		return root;
	}
//	printf("Entering Coalescing + deleteNode with node %p  deleting->size=%d, and root %p of size=%d\n", address, address->size, root, root->size);
	if (address != root)
	{
		if (address->size <= root->size && flag == 0)
		{
		//	printf("Left Enter\n");
			parent = root;
			delete_coalescing(root->left, size, address);
		}
		if (address->size >= root->size && flag == 0)
		{
		//	printf("Right Enter\n");
			parent = root;
			delete_coalescing(root->right, size, address);
		}
	}
	else
	{
		flag = 1;
	//	printf("Found Exact Node  %p with size %d and children as %p %p \n", root, root->size, root->left, root->right);
		if ((root->left == NULL) && (root->right == NULL))
		{
			if (root == free_list_root)
			{
				free_list_root = NULL;
			}
			else
			{
		//		printf("No Child and it's  parent is %p (with children as %p/%p)when root is %p\n", parent, parent->left, parent->right, root);
				if (parent->left == root)
					parent->left = NULL;
				else
					parent->right = NULL;
			}
		}
		else if ((root->left == NULL) || (root->right == NULL)) //Single Child
		{

		//	printf("Single Child with parent %p (it's children as %p/%p)for root as %p\n", parent, parent->left, parent->right, root);
			if (parent == root)
			{
				if (parent->left != NULL)
				{
					free_list_root = parent->left;
					parent->left = NULL;
				}
				else
				{
					free_list_root = parent->right;
					parent->right = NULL;
				}
			}
			else if (parent->left == root)
			{
				if (root->left != NULL)
					parent->left = root->left;
				else
					parent->left = root->right;
			}
			else
			{
				if (root->left != NULL)

					parent->right = root->left;
				else
					parent->right = root->right;
			}
			root->left = NULL;
			root->right = NULL;
		}
		else
		{
			temp_parent = root;
			struct free_block *temp = minValueNode(root->right);
			// printf("Found Replacement %p\n", temp);
		//	printf("Two Children for TEMP(%p)  are :left %p and right %p and temp_parent is %p where parent is %p and root is %p\n", temp, temp->left, temp->left, temp_parent, parent, root);
			// printf("Found Dad of %p is %p\n", temp, parent);
			if (parent == root)
			{
				if (temp_parent == parent)
				{
					temp->left = root->left;
					root->left = NULL;
					root->right = NULL;
					free_list_root = temp;
				}
				else
				{
					temp->left = root->left;
					temp_parent->left = temp->right;
					temp->right = root->right;
					root->left = NULL;
					root->right = NULL;
					free_list_root = temp;
				}
			}
			else if (temp_parent == root)
			{
				if (parent->right == root)
					parent->right = temp;
				else
					parent->left = temp;
				temp->left = root->left;
				root->left = NULL;
				root->right = NULL;
			}
			else
			{
				//printf("Last Case\n");
				if (parent->right == root)
					parent->right = temp;
				else
					parent->left = temp;
				temp_parent->left = temp->right;
				temp->right = root->right;
				temp->left = root->left;
				root->left = NULL;
				root->right = NULL;
			}
			//	printf("\nGlobal Root node is %p(%p/%p)when node is %p\n", free_list_root, free_list_root->left, free_list_root->right, root);
			return NULL;
		}
	}
	//	printf("\nGlobal Root node is %p whent node is %p\n", free_list_root, root);
	if (root == NULL)
	{
		return NULL;
	}
	root->height = 1 + max(height(root->left), height(root->right));

	int balance = getBalance(root);
	if (balance > 1 && getBalance(root->left) > 0)
		return rightRotate(root);
	if (balance > 1 && getBalance(root->left) < 0)
	{
		root->left = leftRotate(root->left);
		return rightRotate(root);
	}
	if (balance < -1 && getBalance(root->right) < 0)
		return leftRotate(root);
	if (balance < -1 && getBalance(root->right) > 0)
	{
		root->right = rightRotate(root->right);
		return leftRotate(root);
	}
	return NULL;
}
