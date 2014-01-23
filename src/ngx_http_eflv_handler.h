
/*
 * Copyright (C) xunen <leixunen@gmail.com>
 * Copyright (C) PublicWRT, Inc.
 */


#ifndef _NGX_HTTP_EFLV_HANDLER_H_INCLUDED_
#define _NGX_HTTP_EFLV_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct{
        size_t start;
        size_t datasize;
} H264VHTag_t;


typedef struct {
        unsigned char signature[3];
        unsigned char version;
        unsigned char flags;
        unsigned char headersize[4];
} FLVFileHeader_t;


typedef struct {
      int hasKeyframes;
      int hasVideo;
      int hasAudio;
      int hasMetadata;
      int hasCuePoints;
      int canSeekToEnd;

      double audiocodecid;
      double audiosamplerate;
      double audiodatarate;
      double audiosamplesize;
      double audiodelay;
      int stereo;

      double videocodecid;
      double framerate;
      double videodatarate;
      double height;
      double width;

      double datasize;
      double audiosize;
      double videosize;
      double filesize;

      double lasttimestamp;
      double lastvideoframetimestamp;
      double lastkeyframetimestamp;
      double lastkeyframelocation;

      int keyframes;
      double *filepositions;
      double *times;
      double duration;

      char metadatacreator[256];
      char creator[256];

      int onmetadatalength;
      int metadatasize;
      size_t onlastsecondlength;
      size_t lastsecondsize;
      int hasLastSecond;
      int lastsecondTagCount;
      size_t onlastkeyframelength;
      size_t lastkeyframesize;
      int hasLastKeyframe;
}FLVMetaData_t;


typedef struct {
        unsigned char type;
        unsigned char datasize[3];
        unsigned char timestamp[3];
        unsigned char timestamp_ex;
        unsigned char streamid[3];
} FLVTag_t;


typedef struct {
        unsigned char flags;
} FLVAudioData_t;


typedef struct {
        unsigned char flags;
} FLVVideoData_t;


#define METADATALEN  327680  // 4048576 1024*320
#define FLV_UI32(x) (int)(((x[0]) << 24) + ((x[1]) << 16) + ((x[2]) << 8) + (x[3]))
#define FLV_UI24(x) (int)(((x[0]) << 16) + ((x[1]) << 8) + (x[2]))
#define FLV_UI16(x) (int)(((x[0]) << 8) + (x[1]))
#define FLV_UI8(x) (int)((x))

#define FLV_AUDIODATA   8
#define FLV_VIDEODATA   9
#define FLV_SCRIPTDATAOBJECT    18

#define FLV_H263VIDEOPACKET     2
#define FLV_SCREENVIDEOPACKET   3
#define FLV_VP6VIDEOPACKET      4
#define FLV_VP6ALPHAVIDEOPACKET 5
#define FLV_SCREENV2VIDEOPACKET 6
#define FLV_AVCVIDEOPACKET      7


#endif /* _NGX_HTTP_EFLV_HANDLER_H_INCLUDED_ */

