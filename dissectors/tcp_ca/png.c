
#include <stdlib.h>
#include <png.h>


static inline void setRGB(png_byte *ptr, float val, int px_size)
{
    int offset, i;
    int v = (int)(val * 768);

    if (v < 0)
        v = 0;
    if (v > 768)
        v = 768;
    offset = v % 256;
    
    if (v<256) {
        for (i=0; i!=px_size; i++) {
            ptr[0+3*i] = 0; 
            ptr[1+3*i] = 0; 
            ptr[2+3*i] = offset;
        }
    }
    else if (v<512) {
        for (i=0; i!=px_size; i++) {
            ptr[0+3*i] = 0;
            ptr[1+3*i] = offset;
            ptr[2+3*i] = 255-offset;
        }
    }
    else {
        for (i=0; i!=px_size; i++) {
            ptr[0+3*i] = offset;
            ptr[1+3*i] = 255-offset;
            ptr[2+3*i] = 0;
        }
    }
}


int WritePng(char *filename, int width, int height, int px_size, float *buffer, char *title)
{
    int code = 0;
    FILE *fp;
    png_structp png_ptr;
    png_infop info_ptr;
    png_bytep row;
    int x, y, i;
	
    // Open file for writing (binary mode)
    fp = fopen(filename, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Could not open file %s for writing\n", filename);
        code = 1;
        goto finalise;
    }

    // Initialize write structure
    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL) {
        fprintf(stderr, "Could not allocate write struct\n");
        code = 1;
        goto finalise;
    }

    // Initialize info structure
    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        fprintf(stderr, "Could not allocate info struct\n");
        code = 1;
        goto finalise;
    }

    // Setup Exception handling
    if (setjmp(png_jmpbuf(png_ptr))) {
        fprintf(stderr, "Error during png creation\n");
        code = 1;
        goto finalise;
    }

    png_init_io(png_ptr, fp);

    // Write header (8 bit colour depth)
    png_set_IHDR(png_ptr, info_ptr, width*px_size, height*px_size,
                 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

    // Set title
    if (title != NULL) {
        png_text title_text;
        title_text.compression = PNG_TEXT_COMPRESSION_NONE;
        title_text.key = "Title";
        title_text.text = title;
        png_set_text(png_ptr, info_ptr, &title_text, 1);
    }

    png_write_info(png_ptr, info_ptr);

    // Allocate memory for one row (3 bytes per pixel - RGB)
    row = (png_bytep) malloc(3 * width * px_size * sizeof(png_byte));

    // Write image data
    for (y=0 ; y<height ; y++) {
        for (x=0 ; x<width ; x++) {
            setRGB(&(row[x*3*px_size]), buffer[y*width + x], px_size);
        }
        for (i=0; i!=px_size; i++)
            png_write_row(png_ptr, row);
    }

    // End write
    png_write_end(png_ptr, NULL);

  finalise:
    if (fp != NULL)
        fclose(fp);
    if (info_ptr != NULL)
        png_free_data(png_ptr, info_ptr, PNG_FREE_ALL, -1);
    if (png_ptr != NULL)
        png_destroy_write_struct(&png_ptr, (png_infopp)NULL);
    if (row != NULL)
        free(row);

    return code;
}

