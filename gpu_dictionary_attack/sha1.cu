/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include <iostream>
#include <string>
#include <fstream>

/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest
#define THREADS 256
#define PASSWORD_MAX_LENGTH	50
#define ALLOCATION_MAX_SIZE 75000000

/**************************** DATA TYPES ****************************/
typedef struct {
	unsigned char data[64];
	unsigned int datalen;
	unsigned long long bitlen;
	unsigned int state[5];
	unsigned int k[4];
} CUDA_SHA1_CTX;

// Struct needed to pass information to device
typedef struct {
	unsigned char word[PASSWORD_MAX_LENGTH];
	unsigned int len;
} PWD_INFO;

/****************************** MACROS ******************************/
#ifndef ROTLEFT
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#endif

// Macro to detect CUDA errors when calling cuda api functions
#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true)
{
   if (code != cudaSuccess) 
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

/*********************** FUNCTION DEFINITIONS ***********************/
__device__  __forceinline__ void cuda_sha1_transform(CUDA_SHA1_CTX *ctx, const unsigned char data[])
{
	unsigned int a, b, c, d, e, i, j, t, m[80];

	// create a 32-bit chunk
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);

	// Extend the chunck up to an 80 bit one
	// From bit 16 to 79, execute this specific modification
	for ( ; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	// Take the state (from init or previous chunk calculation)
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	// Update the state with current chunk calculation
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

__device__ void cuda_sha1_init(CUDA_SHA1_CTX *ctx) {
	// Setting up the initial word and the k variable
	// These constants will be useful for future computation
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

__device__ void cuda_sha1_update(CUDA_SHA1_CTX *ctx, const unsigned char data[], size_t len) {
	size_t i;

	for (i = 0; i < len; ++i) {
		// copy the password in the data field
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;

		// If 64 bytes are reached, we have reached a block (512 bit)
		if (ctx->datalen == 64) {
			// Transform the copied content
			cuda_sha1_transform(ctx, ctx->data);

			// Update the indices to get ready for next block
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__device__ void cuda_sha1_final(CUDA_SHA1_CTX *ctx, unsigned char hash[]) {
	
	unsigned int i;
	i = ctx->datalen;

	// Pad whatever data is left in the buffer since everything
	// needs to be a 512 bit multiple
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		cuda_sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	cuda_sha1_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

__device__ __host__ void makedigits(unsigned char x, unsigned char (&digits)[2]) {
    unsigned char d0 = x / 16;
    digits[1] = x - d0 * 16;
    unsigned char d1 = d0 / 16;
    digits[0] = d0 - d1 * 16;
}

__device__ __host__ void makehex(unsigned char (&digits)[2], char (&hex)[2]) {
    for(int i=0; i<2; ++i) {
        if (digits[i] < 10) {
            hex[i] = '0' + digits[i];
    } else {
            hex[i] = 'a' + (digits[i] - 10);
        }
    }
}

// Main kernel
// The idea is the following: 256 threads per block are spawned. Each thread will compute the hash
// of a single password. It then checks if the resulting hash is equal to the target one.
// If it is, it chagnes the match variable to the index of the found password, otherwise it will
// just end computing and stops.
__global__ void kernel_sha1_hash_BUFFER(PWD_INFO *indata, 
			unsigned int total_threads, 
			unsigned int maxBlock, 
			unsigned char *target, 
			int *match)
{
	// Info about thread/block
	unsigned int bId = blockIdx.x;
	unsigned int tId = threadIdx.x;
	unsigned int thread = bId * blockDim.x + tId;

	// Using register to store the result of the hash
	unsigned char cache[SHA1_BLOCK_SIZE];

	// Stopping condition: # of passwords could not be an exact multiple of 256
	// So the last block needs to stop all threads that which id is higher than the
	// modulo of total_threads by 256 (ex. if last block needs to calculate 64 passwords
	// only the first 64 threads will work, other will exit).
	// With this, I also try to stop other threads to start if a result has already 
	// been found (match is no more == -1).
	if ((bId == maxBlock && tId >= total_threads % THREADS) || *match != -1)
	{
		return;
	}

	// Each thread gets a pwd and calculate the hash on it
	// save the result in the cache variable
	unsigned char* in = indata[thread].word;
	unsigned int len = indata[thread].len;
	CUDA_SHA1_CTX ctx;
	cuda_sha1_init(&ctx);
	cuda_sha1_update(&ctx, in, len);
	cuda_sha1_final(&ctx, cache);

	// Here there is the conversion from an array of unsigned char
	// to a hex string representation. When a single byte is 
	// converted, we check with the target string. If the conversion
	// is different we immediatly stop computing since this is not
	// the hash we're looking for
	for(int i = 0; i < SHA1_BLOCK_SIZE; i++) {
		unsigned char val = cache[i];
		unsigned char d[2];
		char h[2];
		makedigits(val, d);
		makehex(d, h);
		if(target[2*i] != h[0] || target[2*i+1] != h[1]) {
			return;
		}
	}

	// The thread that will "survive" the cycle before will
	// set the match variable with its thread information.
	// Host can now retrieve the clear text password
	*match = thread;
}

void mcm_cuda_sha1_hash_batch_BUFFER(PWD_INFO *cuda_indata, 
			unsigned int buffer_len,
			unsigned char *target,
			int *match
			)
{
	// Threads will be 256 per block (experiments show that it's the better option)
	// The calculation of the blocks will be done based on the amount of passwords to
	// be checked against the target
	unsigned int thread = THREADS;
	unsigned int block = (buffer_len + thread - 1) / thread;
	
	// Kernel call
	kernel_sha1_hash_BUFFER<<< block, thread >>>(cuda_indata, buffer_len, block - 1, target, match);

	// Synchronization
	gpuErrchk( cudaDeviceSynchronize());

	cudaError_t error = cudaGetLastError();
	if (error != cudaSuccess) {
		printf("Error cuda sha1 hash: %s \n", cudaGetErrorString(error));
	}

}

// 1 - Dictionary filename
// 2 - Dictionary dimension
// 3 - Target
int main(int argc, char **argv) {
	char *filename = argv[1];
    std::ifstream passwords(filename);
	std::string line;

	PWD_INFO *cuda_indata;
	PWD_INFO *local_indata;

	int db_size = std::stoi(argv[2]);
	char *target = argv[3];
	unsigned char *d_target;
	
	int h_match = -1;
	int *d_match;

	unsigned int alloc_size = (db_size > ALLOCATION_MAX_SIZE ? ALLOCATION_MAX_SIZE : db_size);

	gpuErrchk( cudaMalloc(&cuda_indata, alloc_size * sizeof(PWD_INFO)));
	local_indata = (PWD_INFO *)malloc(alloc_size * sizeof(PWD_INFO));
	gpuErrchk( cudaMalloc(&d_target, SHA1_BLOCK_SIZE * 2 * sizeof(unsigned char)));
	gpuErrchk( cudaMalloc(&d_match, sizeof(int)));

	// Reading the file and saving the clear text password and its lenght in a
	// PWD_INFO struct. This will then be copied to the device.
	int size = 0;
	while(std::getline(passwords, line)) {
		local_indata[size].len = strlen(line.c_str());
		strcpy((char *)local_indata[size++].word, line.c_str());
	}

	cudaEvent_t start, stop, startKern, stopKern;
	float elapsedTimeKern, elapsedTime;

	// Start measuring time for memory + kernel
	gpuErrchk( cudaEventCreate( &start ) );
	gpuErrchk( cudaEventCreate( &stop ) );
	gpuErrchk( cudaEventRecord( start, 0 ) );

	// Copying data from host to memory: array of PWD_INFO, target hash 
	// and the variable for the index of the (possibly) found password
	gpuErrchk( cudaMemcpy(cuda_indata, local_indata, alloc_size * sizeof(PWD_INFO), cudaMemcpyHostToDevice));
	gpuErrchk( cudaMemcpy(d_target, target, SHA1_BLOCK_SIZE * 2 * sizeof(unsigned char), cudaMemcpyHostToDevice));
	gpuErrchk( cudaMemcpy(d_match, &h_match, sizeof(int), cudaMemcpyHostToDevice));

	// Start measuring time for just kernel
	gpuErrchk( cudaEventCreate( &startKern ) );
	gpuErrchk( cudaEventCreate( &stopKern ) );
	gpuErrchk( cudaEventRecord( startKern, 0 ) );

	// Wrapper that internally calls the kernel
	mcm_cuda_sha1_hash_batch_BUFFER(cuda_indata, size, d_target, d_match);

	// Stopping measuring time for just kernel and printing results
	gpuErrchk( cudaEventRecord( stopKern, 0 ) );
	gpuErrchk( cudaEventSynchronize( stopKern ) );
	gpuErrchk( cudaEventElapsedTime( &elapsedTimeKern, startKern, stopKern ) );
	printf( "Kernel timing: %3.1f ms\n", elapsedTimeKern );

	// Copying index result from device to host. No need to copy back the whole 
	// PWD_INFO array since it is no more useful to the host (or better, it is unchanged)
	gpuErrchk( cudaMemcpy(&h_match, d_match, sizeof(int), cudaMemcpyDeviceToHost));

	// Stopping measuring time for just kernel and printing results
	gpuErrchk( cudaEventRecord( stop, 0 ) );
	gpuErrchk( cudaEventSynchronize( stop ) );
	gpuErrchk( cudaEventElapsedTime( &elapsedTime, start, stop ) );
	printf( "Kernel + memory timing: %3.1f ms\n", elapsedTime );

	// Destroying event handlers
	gpuErrchk( cudaEventDestroy( startKern ) );
	gpuErrchk( cudaEventDestroy( stopKern ) );
	gpuErrchk( cudaEventDestroy( start ) );
	gpuErrchk( cudaEventDestroy( stop ) );

	// Displaying the result
    if(h_match == -1) {
        std::cout << "Password not in database" << std::endl;
    } else {
	    std::cout << "Password is " << local_indata[h_match].word << std::endl;
    }

	// Freeing all the pointers (device and host) dynamically allocated
	gpuErrchk( cudaFree(cuda_indata));
	gpuErrchk( cudaFree(d_match));
	gpuErrchk( cudaFree(d_target));
	free(local_indata);

    return 0;
}