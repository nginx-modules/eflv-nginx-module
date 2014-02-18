/*
 * Copyright (C) ywby
 * Copyright (C) xunen <leixunen@gmail.com>
 * Copyright (C) PublicWRT, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include "ngx_http_eflv_handler.h"


static void revert_int(char *s, const char *d, int len);
ngx_int_t readFLVSecondPass(char *flv, size_t streampos, double filesize, H264VHTag_t *pFirstMetaDataTag);
static char *get_position_ptr(char *str_src, size_t str_len, size_t filesize, const char *str_dest);
static double get_real_value( const char *times, const char *filepos, int num, const double value, int start_index, int *ret_index, double *ret_time);
static int time_drag_position(char *flv, double *start, double *end, double filesize, ngx_int_t have_end, FLVMetaData_t *drag_FLVMetaData, double **key_times, double **key_filepos, ngx_http_request_t *r);


static u_char  ngx_flv_header[] = "FLV\x1\x1\0\0\0\x9\0\0\0\x9";


static void
revert_int(char *s, const char *d, int len)
{
        int i = 0;
        for(i = len -1 ; i >= 0; i--) {
                *(s+i) = *d;
                d++;
        }
}


static int
readFLVFirstPass(char *flv, size_t streampos, size_t filesize, H264VHTag_t *pFirstH264VideoTag, H264VHTag_t *pFirstH264Audio)
{
	size_t datasize, videosize = 0, audiosize = 0;
	size_t videotags = 0, audiotags = 0;
	FLVTag_t *flvtag;
	FLVVideoData_t *flvvideo;

	pFirstH264VideoTag->start = 0;
	pFirstH264Audio->start = 0;

	for(;;) {
		if(streampos + sizeof(FLVTag_t) > filesize)
			break;

		flvtag = (FLVTag_t *)&flv[streampos];

		// TagHeader + TagData + PreviousTagSize
		datasize = sizeof(FLVTag_t) + FLV_UI24(flvtag->datasize) + 4;

		if(streampos + datasize > filesize)
			break;

		if(flvtag->type == FLV_AUDIODATA) {

			audiosize += FLV_UI24(flvtag->datasize);
			audiotags++;
			if (pFirstH264Audio->start == 0)
			{
				pFirstH264Audio->start=streampos;
				pFirstH264Audio->datasize=datasize;
			}

			if (pFirstH264VideoTag->start>0)
			{
				return 1;
			}
		}
		else if(flvtag->type == FLV_VIDEODATA) {
			//flvmetadata.datasize += (double)datasize;
			//// datasize - PreviousTagSize
			//flvmetadata.videosize += (double)(datasize - 4);

			videosize += FLV_UI24(flvtag->datasize);
			videotags++;

			flvvideo = (FLVVideoData_t *)&flv[streampos + sizeof(FLVTag_t)];


			switch(flvvideo->flags & 0xf) {
					case FLV_AVCVIDEOPACKET:
						if (pFirstH264VideoTag->start == 0)
						{
							pFirstH264VideoTag->start=streampos;
							pFirstH264VideoTag->datasize=datasize;
						}
						if (pFirstH264Audio->start>0)
						{
							return 1;
						}

						break;
					default:
						//fprintf(stderr, "Couldn't support the encoding format.\n");
						return 0;
						break;
			}

		}
		streampos += datasize;
	}
	return 0;
}


ngx_int_t
readFLVSecondPass(char *flv, size_t streampos, double filesize, H264VHTag_t *pFirstMetaDataTag)
{
        size_t datasize,  audiosize = 0;
        size_t  audiotags = 0;
        FLVTag_t *flvtag;

        pFirstMetaDataTag->start = 0;
        for(;;) {
                if(streampos + sizeof(FLVTag_t) > filesize)
                        break;

                flvtag = (FLVTag_t *)&flv[streampos];

                //TagHeader + TagData + PreviousTagSize       
                datasize = sizeof(FLVTag_t) + FLV_UI24(flvtag->datasize) + 4;

                if(streampos + datasize > filesize)
                        break;

                if(flvtag->type == FLV_SCRIPTDATAOBJECT) {

                        audiosize += FLV_UI24(flvtag->datasize);
                        audiotags++;
                        if (pFirstMetaDataTag->start == 0)
                        {
                                pFirstMetaDataTag->start=streampos;
                                pFirstMetaDataTag->datasize=datasize;
                        }

                        if (pFirstMetaDataTag->start>0)
                        {
                                return 1;
                        }
                }
		streampos += datasize;

	}
	return 0;
}


static char *
get_position_ptr(char *str_src, size_t str_len, size_t filesize, const char *str_dest)
{
	if (str_src == NULL || str_dest == NULL){
                return NULL;
        }

        char buf[METADATALEN] = {0};
	size_t  i = 0, size = 0;
        int iLen = 0;
	char *p = NULL;
	//size_t filesize_tmp = str_len;
	int i_cpoy_len = 0;
	char *buf_tmp = buf;	
		
		i = 0;
		size = 0;
        	i_cpoy_len = 0;
		bzero(buf,sizeof(buf));
		if (filesize <=str_len){
			memcpy(buf,str_src,filesize);
		}
		else{
			memcpy(buf,str_src,str_len);
		}
		buf_tmp = buf;
		
		//处理4K内容里有字符结束符	
		while(1){
			p =strstr(buf_tmp,str_dest);
			if (p == NULL){
				i = strlen(buf_tmp);
				buf_tmp = buf_tmp + i;
				size+=(i+1);
				iLen+=(i+1);	
				
				//处理 buf =  字符串A + 0x0 + 字符串B
				if(size >= str_len){
                                	return NULL;
                        	}	
				
				//有符号 0x0 
				buf_tmp = buf_tmp+1;
				//size++;
				//iLen ++;
			}
			else{
				//找到偏移值
				iLen = iLen + (p -buf_tmp)*sizeof(char);
				
				p = str_src+iLen; 
				return p;
			}
			
		}
	return NULL;
}


/*
        函数: static double get_real_value(const char *times,const char *filepos,int num,const double value)
        功能：通过times数组中，找出最接近value的索引，通过该索引找出filepos的值,该值作为文件位置偏移地址返回
        输入：times   	字符串指针，metadata信息中时间偏移的指针
              filepos   字符串指针，metadata信息中位置偏移的指针
              num     	整型,关键帧个数
              value 	double型,要与times数组比较的值
	      start_index 整型,上次找到关键帧索引
	      ret_index 整型指针,本次找到关键帧索引
	      ret_time  整型指针，返回本次时间索引对应的时间值
	返回：-1 --返回地址失败 非-1 -- 返回文件位置偏移值
             
*/
static double
get_real_value(const char *times, const char *filepos, int num, const double value, int start_index, int *ret_index, double *ret_time)
{
	
	if ((times ==NULL) || (filepos == NULL) || (ret_index == NULL) || (ret_time == NULL)){
		return -1;
	}
	int i  = 0,min_index=0, max_index=0, j=0;
	double temp = 0,min_value = 0;
	char rbuf[32] = {0};
	double file_pos = 0;
	
	for(i=0; ;i++)	{
		if(times[10+i*9] == 0)
			break;
		if(i > num){
			return -1;	
		}
	}

	min_index = 0;
	max_index = num-1; 
	j = 0;
	double timepos = 0;
	for(i=1;;i++)
        {
		if (((max_index - min_index) < 2) || (timepos == value) )
			break;

		if(times[10+((min_index+max_index)/2+j)*9] != 0){
			if(((min_index+max_index)/2+j) >= max_index){
				break;
			}
			else {
				j += 1;
				continue;
			}
		}

		timepos = 0;
		revert_int(rbuf, &times[10+((min_index+max_index)/2+j)*9+1], 8);
		memcpy(&timepos, &rbuf, 8);
	
		if(timepos < value){
			min_index = (min_index+max_index)/2+j;
		}
		else if (timepos >=value){
			max_index = (min_index+max_index)/2+j;
		}
		j = 0;
        }

	revert_int(rbuf, &times[10+min_index*9+1],8);
	memcpy(&min_value, &rbuf, 8);
	revert_int(rbuf, &times[10+max_index*9+1],8);
	memcpy(&temp, &rbuf, 8);
	
	if (value > temp){
		min_index = num - 1;				
	}
	
	if ((start_index != -1) && start_index == min_index){
		min_index = min_index + 1;	
		if (min_index>=num){
			return -2;
		}
	}
	
	revert_int(rbuf, &times[10+min_index*9+1],8);
	memcpy(&min_value, &rbuf, 8);

	*ret_time = min_value;
	
	double timepos2 = 0;
	revert_int(rbuf, &filepos[18+min_index*9+1],8);
	memcpy(&timepos2, &rbuf, 8);
	file_pos = timepos2;
		
	if (start_index != -1 ){
		file_pos = file_pos - 1;
	}
	
	(*ret_index) = min_index ;
	return file_pos;
}

/*
        函数:static int  time_drag_position(const char *flv ,double *start,double *end,size_t filesize,const int have_end)
        输入：flv   字符串指针,mmap文件后，该文件内存映射的地址
              start double型指针 ,参数start所带的值 
              end   double型指针 ,参数end所带的值 
              filesize size_t, 文件大小
              have_end 整型,url中是否带end参数:1 --带end参数 0 --不带end参数
	返回：
              0 --按时间值分析成功  -1 --按时间值分析失败 
*/
static int
time_drag_position(char *flv, double *start, double *end, double filesize, ngx_int_t have_end, FLVMetaData_t *drag_FLVMetaData, double **key_times, double **key_filepos, ngx_http_request_t *r)
{
	double temp =0;
	double file_pos = 0;
	if ((flv == NULL) || (start == NULL) || (end == NULL) || (drag_FLVMetaData == NULL) ){
		return -1;
	}
       	char *keyframes = get_position_ptr(flv,METADATALEN,filesize,"keyframes"); 
	if (keyframes == NULL){
		return -1;	
	}
	char *times = get_position_ptr(keyframes,METADATALEN,filesize,"times");	
	if ( times == NULL){
		
		return -1;
	}
	
	if (times[5] != 10){
		return -1;
	}	
	
	char rbuf[32] = {0};
	unsigned int keyframes_num = 0;
	revert_int(rbuf, &times[6],4);
	memcpy(&keyframes_num, &rbuf,4);

	char *filepositions = get_position_ptr(keyframes,METADATALEN,filesize,"filepositions");	
	if(filepositions == NULL){
		return -1;
	}
	if (filepositions[13] != 10){
                return -1;
	}	

	char *p_duration = get_position_ptr(flv,METADATALEN,filesize,"duration");	
	if (p_duration == NULL){
		revert_int(rbuf, &times[10+(keyframes_num-1)*9+1],8);
                memcpy(&temp, &rbuf, 8);			
	}
	else{
		revert_int(rbuf, &p_duration[9],8);
		memcpy(&temp, &rbuf, 8);	
	}
	
	int index = 0;
	double start_time = 0, end_time = 0;	
	int start_key_index = 0;
	double start_tmp = 0;	
		
	if (*start >temp){
		*start = 0;	
	}	
	start_tmp = *start;
	
	file_pos = get_real_value(times,filepositions,keyframes_num,*start,-1,&index,&start_time);
	if (file_pos == -1){
		return -1;
	}
	if (file_pos >0 && file_pos <=filesize){
		*start = file_pos;
	}
	
	if (index >=0){
		start_key_index = index;
	}
	else{
		start_key_index = 0;
	}
	
	if (have_end == 1){
		if (((start_tmp) > (*end)) || ((*end) > temp)){
			*end = filesize;
			drag_FLVMetaData->duration = temp - start_time ;
		}
		else{
			file_pos = get_real_value(times,filepositions,keyframes_num,*end,start_key_index,&index,&end_time);
			if (file_pos == -1){
				return -1;
			}	
			else if (file_pos == -2){
				*end = filesize;	
				drag_FLVMetaData->duration = temp - start_time ;
			}
			else if (file_pos >0 && file_pos <=filesize){
				*end = file_pos;
				drag_FLVMetaData->duration = end_time - start_time ;
			}
			else{
			
			}
		}	
		
	}
	else{
		
		drag_FLVMetaData->duration = temp - start_time ;
	}
	
	return 0;
}


static size_t
swap_duration(char *p_buf, double value)
{
union {
            unsigned char dc[8];
            double dd;
      } d;

      if (p_buf == NULL){

             return -1;
     }
     unsigned char b[8];
      size_t datasize = 0;

      d.dd = value;

      b[0] = d.dc[7];
      b[1] = d.dc[6];
      b[2] = d.dc[5];
      b[3] = d.dc[4];
      b[4] = d.dc[3];
      b[5] = d.dc[2];
      b[6] = d.dc[1];
      b[7] = d.dc[0];

      //datasize += fwrite(b, 1, 8, fp);

      memcpy(p_buf,b,sizeof(char)*8);
      datasize += 8;
      return datasize;
}


static void 
ntx_htt_sflv_metadata(ngx_int_t fd, double len, char *send_tH264VideoTag_buf, char *send_tH264AudioTag_buf, ngx_int_t *video_size, ngx_int_t *audio_size, ngx_http_request_t *r)
{
    size_t  streampos;
    H264VHTag_t tH264VideoTag,tH264AudioTag; 
    bzero(&tH264VideoTag,sizeof(tH264VideoTag));
    bzero(&tH264AudioTag,sizeof(tH264AudioTag)); 
    FLVFileHeader_t *flvfileheader;
    char flv[METADATALEN] ={0}; 
    ngx_int_t n; 
    ngx_int_t i_read; 
    ngx_log_t    *log; 
    log = r->connection->log; 

    i_read = METADATALEN; 
    if (len< METADATALEN){
    	i_read = len;	
    } 
    n = read((int)fd,flv,i_read); 
    
    if ( -1 == n){
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                           "ngx_flvposition_read"  " \"%d\" failed", (int)fd);
    }
 
    flvfileheader = (FLVFileHeader_t *)flv;
    streampos = FLV_UI32(flvfileheader->headersize) + 4;
    
    readFLVFirstPass(flv, streampos, METADATALEN,&tH264VideoTag,&tH264AudioTag);
    *video_size = (ngx_int_t)tH264VideoTag.datasize;
    *audio_size = (ngx_int_t)tH264AudioTag.datasize; 
    if (tH264VideoTag.start > 0) {
  	memcpy(send_tH264VideoTag_buf, flv+tH264VideoTag.start,tH264VideoTag.datasize);
    }
    if (tH264AudioTag.start > 0) {
	    memcpy(send_tH264AudioTag_buf, flv+tH264AudioTag.start,tH264AudioTag.datasize);
    } 
}


static ngx_int_t
ntx_htt_tflv_metadata(ngx_int_t fd, double *start, double *end, ngx_int_t have_end, double len, char *send_metadata_buf, char *send_tH264VideoTag_buf, char *send_tH264AudioTag_buf, ngx_int_t *video_size, ngx_int_t *audio_size, ngx_http_request_t *r)
{
    size_t  streampos;
    H264VHTag_t tH264VideoTag,tH264AudioTag; 
    bzero(&tH264VideoTag,sizeof(tH264VideoTag));
    bzero(&tH264AudioTag,sizeof(tH264AudioTag));
 
    FLVMetaData_t drag_FLVMetaData;
    bzero(&drag_FLVMetaData,sizeof(FLVMetaData_t)); 
    FLVFileHeader_t *flvfileheader;
    H264VHTag_t tMetaDataTag; 
    double *key_times = NULL;
    double *key_filepos =NULL;
    char flv[METADATALEN] ={0}; 
    ngx_int_t n; 
    ngx_int_t i_read; 
    ngx_log_t    *log; 
    log = r->connection->log; 
    //flv = mmap(NULL, len, PROT_READ, MAP_PRIVATE, (int)fd, 0);
    i_read = METADATALEN; 
    if (len< METADATALEN){
    	i_read = len;	
    } 
    n = read((int)fd,flv,i_read); 
    
    if ( -1 == n){
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                           "ngx_flv_read"  " \"%d\" failed", (int)fd);
    }
 
    flvfileheader = (FLVFileHeader_t *)flv;
    streampos = FLV_UI32(flvfileheader->headersize) + 4;
    
    time_drag_position(flv,start,end,len,have_end,&drag_FLVMetaData,&key_times,&key_filepos,r);
    readFLVSecondPass(flv, streampos, len,&tMetaDataTag);
    if (tMetaDataTag.start > 0) {
            char *p_duration = NULL;
            if (tMetaDataTag.datasize <=METADATALEN){
                    memcpy(send_metadata_buf,flv+tMetaDataTag.start,tMetaDataTag.datasize);
                    p_duration= get_position_ptr(send_metadata_buf,METADATALEN,len,"duration"); 
		    if (p_duration != NULL){
                            p_duration = p_duration+9;
                            swap_duration(p_duration,drag_FLVMetaData.duration);
                    }
            }
    }
    //munmap(flv,len); 
    
    readFLVFirstPass(flv, streampos, METADATALEN,&tH264VideoTag,&tH264AudioTag);
    *video_size = (ngx_int_t)tH264VideoTag.datasize;
    *audio_size = (ngx_int_t)tH264AudioTag.datasize; 
    if (tH264VideoTag.start > 0) {
  	memcpy(send_tH264VideoTag_buf, flv+tH264VideoTag.start,tH264VideoTag.datasize);
    }
    if (tH264AudioTag.start > 0) {
	    memcpy(send_tH264AudioTag_buf, flv+tH264AudioTag.start,tH264AudioTag.datasize);
    } 
    return (ngx_int_t)tMetaDataTag.datasize;
}


ngx_int_t
ngx_http_tflv_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    double                     start =0,end =0, len;
    size_t                     root;
    ngx_int_t                  rc;
    ngx_uint_t                 level,  i,j;
    ngx_str_t                  path, value;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out[5];
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    char send_metadata_buf[METADATALEN] = {0};
    char send_tH264VideoTag_buf[METADATALEN] = {0};
    char send_tH264AudioTag_buf[METADATALEN] = {0};
    ngx_int_t  video_size =0;
    ngx_int_t  audio_size =0; 
   
    ngx_int_t i_have_start = 0;
    ngx_int_t i_have_end = 0;
 
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;
    i = 0;
    j = 0;

	if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {

            i_have_start = 1;

            start = ngx_atoof(value.data, value.len);

            if (start > len){
	   	return NGX_DECLINED; 
	    }

            if (start == NGX_ERROR) {
                start = 0;
            }

        }


	end = len;
        if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK) {
            i_have_end = 1;

            end = ngx_atoof(value.data, value.len);
            if (end == NGX_ERROR || (end > len)) {
                i_have_end = 0;
                end = len;
            }
        }

        if ((0 == i_have_start) && (0 == i_have_end)){
	}
  
    	ngx_int_t meta_size = ntx_htt_tflv_metadata(of.fd,&start,&end,i_have_end,len,send_metadata_buf,send_tH264VideoTag_buf,send_tH264AudioTag_buf,&video_size,&audio_size, r); 
      
	log->action = "sending flvtime to client";
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.last_modified_time = of.mtime;

	if (ngx_http_set_content_type(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	b->pos = ngx_flv_header;
	b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
	b->memory = 1;

	out[j].buf = b;
	out[j].next = &out[j+1];
	j++;

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));  
	b->pos = (u_char*)send_metadata_buf;  
	b->last = (u_char*)(send_metadata_buf + meta_size);  
	b->memory = 1;  
	out[j].buf = b;
	out[j].next = &out[j+1];
	j++;

	if (video_size !=0){
		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));  
		b->pos = (u_char*)send_tH264VideoTag_buf;  
		b->last = (u_char*)(send_tH264VideoTag_buf + video_size);  
		b->memory = 1;  
		out[j].buf = b;
		out[j].next = &out[j+1];
		j++;
	}

	if (audio_size !=0){
		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));  
		b->pos = (u_char*)send_tH264AudioTag_buf;  
		b->last = (u_char*)(send_tH264AudioTag_buf + audio_size);  
		b->memory = 1;  
		out[j].buf = b;
		out[j].next = &out[j+1];
		j++;
	}

	r->headers_out.content_length_n =sizeof(ngx_flv_header) - 1 + meta_size + end -start + video_size + audio_size;

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
	if (b->file == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//r->allow_ranges = 1;
	r->allow_ranges = 1;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	b->file_pos = (off_t)start;
	b->file_last = (off_t)end;

	b->in_file = b->file_last ? 1: 0;
	b->last_buf = 1;
	b->last_in_chain = 1;

	b->file->fd = of.fd;
	b->file->name = path;
	b->file->log = log;
	b->file->directio = of.is_directio;

	out[j].buf = b;
	out[j].next = NULL;
    
    	return ngx_http_output_filter(r, &out[i]);
}


ngx_int_t
ngx_http_sflv_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    double                     start =0,end =0, len;
    size_t                     root;
    ngx_int_t                  rc;
    ngx_uint_t                 level, i,j;
    ngx_str_t                  path, value;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out[4];
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    char send_tH264VideoTag_buf[METADATALEN] = {0};
    char send_tH264AudioTag_buf[METADATALEN] = {0};
    ngx_int_t  video_size =0;
    ngx_int_t  audio_size =0; 
   
    i= 0; 
    j= 0; 
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;


	if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {

            start = ngx_atoof(value.data, value.len);

            if (start > len){
	   	return NGX_DECLINED; 
	    }

            if (start == NGX_ERROR) {
                start = 0;
            }

        }

	end = len;
        if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK) {

	    /*2013-08-22 by ywby*/
            end = ngx_atoof(value.data, value.len) + 1;
            if (end == NGX_ERROR || (end > len)) {
                end = len;
            }
        }
      
	log->action = "sending flvposition to client";
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.last_modified_time = of.mtime;

	if (ngx_http_set_content_type(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if ( start != 0){ 
		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		b->pos = ngx_flv_header;
		b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
		b->memory = 1;

		out[j].buf = b;
		out[j].next = &out[j+1];
		j++;
	
    		ntx_htt_sflv_metadata(of.fd,len,send_tH264VideoTag_buf,send_tH264AudioTag_buf,&video_size,&audio_size, r); 

		if (video_size != 0 ){ 
			b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));  
			b->pos = (u_char*)send_tH264VideoTag_buf;  
			b->last = (u_char*)(send_tH264VideoTag_buf + video_size);  
			b->memory = 1;  
			out[j].buf = b;
			out[j].next = &out[j+1];
			j++;
		}	
	
		if ( audio_size != 0 ){
			b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));  
			b->pos = (u_char*)send_tH264AudioTag_buf;  
			b->last = (u_char*)(send_tH264AudioTag_buf + audio_size);  
			b->memory = 1;  
			out[j].buf = b;
			out[j].next = &out[j+1];
			j++;
		}
	
		if (start > end){
			end = len;	
		}
		
		//sizeof(ngx_flv_header) - 1 + meta_size + end -start + video_size + audio_size;
		r->headers_out.content_length_n =sizeof(ngx_flv_header) - 1 + end -start + video_size + audio_size;

		//r->allow_ranges = 1;
		r->allow_ranges = 1;
		rc = ngx_http_send_header(r);
		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}
		
		if ((start != len) &&  (start != end)){	
			b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
			if (b == NULL) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
			if (b->file == NULL) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			b->file_pos = (off_t)start;
			b->file_last = (off_t)end;

			b->in_file = b->file_last ? 1: 0;
			b->last_buf = 1;
			b->last_in_chain = 1;

			b->file->fd = of.fd;
			b->file->name = path;
			b->file->log = log;
			b->file->directio = of.is_directio;

			out[j].buf = b;
			out[j].next = NULL;
		}
		else{
			 b->last_buf = 1;
                         b->last_in_chain = 1;	
			 out[--j].next = NULL;
		}	
	}
	else{
		//sizeof(ngx_flv_header) - 1 + meta_size + end -start + video_size + audio_size;
		r->headers_out.content_length_n = end -start;

		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
		if (b->file == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		//r->allow_ranges = 1;
		r->allow_ranges = 1;
		rc = ngx_http_send_header(r);
		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}

		b->file_pos = (off_t)start;
		b->file_last = (off_t)end;

		b->in_file = b->file_last ? 1: 0;
		b->last_buf = 1;
		b->last_in_chain = 1;

		b->file->fd = of.fd;
		b->file->name = path;
		b->file->log = log;
		b->file->directio = of.is_directio;

		out[0].buf = b;
		out[0].next = NULL;
	} 
    	
	return ngx_http_output_filter(r, &out[i]);
}

