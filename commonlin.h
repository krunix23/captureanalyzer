/*
 *  Net Filter GigEVision Protocol
 *  Copyright(c) 2009 by MATRIX VISION GmbH <info@matrix-vision.de> 
 *  Author: MRA
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#ifndef __COMMONLIN_H__
#define __COMMONLIN_H__

typedef int FilDes;
typedef uint64_t ULONG;
typedef uint64_t* PULONG;

#define MVNF_IOCTL_MAGIC		'f'
#define _MVNFIOt(n)					_IO(MVNF_IOCTL_MAGIC,n)
#define _MVNFIORt(n,t)			_IOR(MVNF_IOCTL_MAGIC,n,t)
#define _MVNFIOWt(n,t)			_IOW(MVNF_IOCTL_MAGIC,n,t)

#define NETFILTER_GET_SOURCE_ADDR		_MVNFIORt( 1, __u32)
#define NETFILTER_SET_SOURCE_ADDR		_MVNFIOWt( 2, __u32)
#define NETFILTER_GET_DEST_PORT			_MVNFIORt( 3, __u32)
#define NETFILTER_SET_DEST_PORT			_MVNFIOWt( 4, __u32)
#define NETFILTER_GET_MODE					_MVNFIORt( 5, __u32)
#define NETFILTER_SET_MODE					_MVNFIOWt( 6, __u32)
#define NETFILTER_GET_PACKETSIZE		_MVNFIORt( 7, __u32)
#define NETFILTER_SET_PACKETSIZE		_MVNFIOWt( 8, __u32)
#define NETFILTER_GET_FILTERMODE		_MVNFIORt( 9, __u32)
#define NETFILTER_SET_FILTERMODE		_MVNFIOWt(10, __u32)
#define NETFILTER_ANOUNCE_BUFFER		_MVNFIOWt(11, __u32)
#define NETFILTER_GET_BUFFER				_MVNFIORt(12, __u32)
#define NETFILTER_CLEAN_QUEUES			_MVNFIOWt(13, __u32)
#define NETFILTER_GET_DEST_ADDR			_MVNFIORt(14, __u32)
#define NETFILTER_SET_DEST_ADDR			_MVNFIOWt(15, __u32)
#define NETFILTER_GET_SOURCE_PORT		_MVNFIORt(16, __u32)
#define NETFILTER_SET_SOURCE_PORT		_MVNFIOWt(17, __u32)
#define NETFILTER_SET_STREAM_CH			_MVNFIOWt(18, __u32)
#define NETFILTER_GET_STREAM_CH			_MVNFIORt(19, __u32)

#define ANALYZER_LIST_DEVICES								_MVNFIORt(30, __u32)
#define ANALYZER_BIND_FILTER								_MVNFIOWt(31, __u32)
#define ANALYZER_GET_STATISTICS							_MVNFIORt(32, __u32)
#define ANALYZER_GET_FILTER_STATISTICS			_MVNFIORt(33, __u32)
#define ANALYZER_RESET_FILTER_STATISTICS		_MVNFIOWt(34, __u32)
#define ANALYZER_GET_IPv4_STATISTICS				_MVNFIORt(35, __u32)
#define ANALYZER_RESET_IPv4_STATISTICS			_MVNFIOWt(36, __u32)
#define ANALYZER_GET_RESEND_STATISTICS			_MVNFIORt(37, __u32)
#define ANALYZER_RESET_RESEND_STATISTICS		_MVNFIOWt(38, __u32)
#define ANALYZER_GET_FILTER_INFO						_MVNFIORt(39, __u32)

#define NETFILTER_TOUCH_BUFFER			_MVNFIOWt(50, __u32)

#ifdef CONFIG_COMPAT
#define NETFILTER_GET_SOURCE_ADDR32		_MVNFIORt( 1, __u32)
#define NETFILTER_SET_SOURCE_ADDR32		_MVNFIOWt( 2, __u32)
#define NETFILTER_GET_DEST_PORT32			_MVNFIORt( 3, __u32)
#define NETFILTER_SET_DEST_PORT32			_MVNFIOWt( 4, __u32)
#define NETFILTER_GET_MODE32					_MVNFIORt( 5, __u32)
#define NETFILTER_SET_MODE32					_MVNFIOWt( 6, __u32)
#define NETFILTER_GET_PACKETSIZE32		_MVNFIORt( 7, __u32)
#define NETFILTER_SET_PACKETSIZE32		_MVNFIOWt( 8, __u32)
#define NETFILTER_GET_FILTERMODE32		_MVNFIORt( 9, __u32)
#define NETFILTER_SET_FILTERMODE32		_MVNFIOWt(10, __u32)
#define NETFILTER_ANOUNCE_BUFFER32		_MVNFIOWt(11, __u32)
#define NETFILTER_GET_BUFFER32				_MVNFIORt(12, __u32)
#define NETFILTER_CLEAN_QUEUES32			_MVNFIOWt(13, __u32)
#define NETFILTER_GET_DEST_ADDR32			_MVNFIORt(14, __u32)
#define NETFILTER_SET_DEST_ADDR32			_MVNFIOWt(15, __u32)
#define NETFILTER_GET_SOURCE_PORT32		_MVNFIORt(16, __u32)
#define NETFILTER_SET_SOURCE_PORT32		_MVNFIOWt(17, __u32)
#define NETFILTER_SET_STREAM_CH32			_MVNFIOWt(18, __u32)
#define NETFILTER_GET_STREAM_CH32			_MVNFIORt(19, __u32)

#define ANALYZER_LIST_DEVICES32							_MVNFIORt(30, __u32)
#define ANALYZER_BIND_FILTER32							_MVNFIOWt(31, __u32)
#define ANALYZER_GET_STATISTICS32						_MVNFIORt(32, __u32)
#define ANALYZER_GET_FILTER_STATISTICS32		_MVNFIORt(33, __u32)
#define ANALYZER_RESET_FILTER_STATISTICS32	_MVNFIOWt(34, __u32)
#define ANALYZER_GET_IPv4_STATISTICS32			_MVNFIORt(35, __u32)
#define ANALYZER_RESET_IPv4_STATISTICS32		_MVNFIOWt(36, __u32)
#define ANALYZER_GET_RESEND_STATISTICS32		_MVNFIORt(37, __u32)
#define ANALYZER_RESET_RESEND_STATISTICS32	_MVNFIOWt(38, __u32)
#define ANALYZER_GET_FILTER_INFO32					_MVNFIORt(39, __u32)
#endif

struct _IPv4AddrStats
{
	uint64_t StructSize_bytes;
	uint64_t MPSendPktsCt;      // Packets through MPSendPackets.
	uint64_t MPSendPktsDropped; // Packets dropped in MPSendPackets.
	uint64_t PTRcvCt;           // Packets through PTReceive.
	uint64_t PTRcvDropped;      // Packets dropped in PTReceive.
	uint64_t PTRcvPktCt;        // Packets through PTReceivePacket.
	uint64_t PTRcvPktDropped;   // Packets dropped in PTReceivePacket.
	uint64_t PktBytesCopied;    // Pkt Bytes copied
	uint64_t PktDroppedByPacketDropper; // can be configured via 'AdapterSpecificTestParameters'
};
typedef struct _IPv4AddrStats IPv4AddrStats;
typedef struct _IPv4AddrStats *PIPv4AddrStats;

struct _GigEVisionPacketsType
{
	uint64_t StructSize_bytes;
	uint64_t Leaders;
	uint64_t Trailers;
	uint64_t Payload;
	uint64_t Duplicate;
	uint64_t Unknown;
};
typedef struct _GigEVisionPacketsType GigEVisionPacketsType;

struct _FrameStatisticsType
{
	uint64_t StructSize_bytes;
	uint64_t MissingLeaders;
	uint64_t MissingTrailers;
	uint64_t MissingPayloadPackets;
	uint64_t FaultyImages;
	uint64_t CompleteFrames;
	uint64_t IncompleteFrames;
	uint64_t ReconstructedFrames; // via resend
	uint64_t UnsuccessfullyReconstructedFrames; // resend has been tried but still the frame could not be reconstructed
	uint64_t LostFrames; // because no buffer was available 
};
typedef struct _FrameStatisticsType FrameStatisticsType;

struct _BufferStatisticsType
{
	uint64_t StructSize_bytes;
	uint64_t AnnouncedBufferCnt;
	int64_t  BuffersInQueue;
	uint64_t QueuedBufferCnt;
	uint64_t CanceledBufferCnt;
	uint64_t TimedOutBufferCnt;
	uint64_t SuccessfulBufferCnt;
	uint64_t UnknownErrorBufferCnt;
	uint64_t InvalidIOBuffer;
};
typedef struct _BufferStatisticsType BufferStatisticsType;

struct _ResendStatisticsType
{
	uint64_t StructSize_bytes;
	uint64_t ResendCmdsIssued;
	uint64_t ReRequestedPacketCnt;
	uint64_t RecoveredPacketCnt;
	uint64_t SingleGapsCnt;
	uint64_t MultiGapCnt;
	uint64_t LargestGapSize;
	uint64_t PushBufferToOldQueueCnt;
	uint64_t ResendTriggeredByHoleDetectCnt;
	uint64_t ResendTriggeredByPacketRxCnt;
	uint64_t ResendTriggeredBySystemTimerCnt;
	uint64_t ResendTriggeredByPacketTimerCnt;
	uint64_t ResendTxStateCnt[4];
	uint64_t ResendRxStateCnt[4];
	uint64_t Reserved[4];
};
typedef struct _ResendStatisticsType ResendStatisticsType;
typedef struct _ResendStatisticsType  *PResendStatisticsType;

struct _FilterStatisticsType
{
	uint64_t StructSize_bytes;
	GigEVisionPacketsType DroppedPackets; // because of no buffer;
	GigEVisionPacketsType ProcessedPackets;
	FrameStatisticsType FrameStatistics;
	BufferStatisticsType BufferStatistics;
};
typedef struct _FilterStatisticsType FilterStatistics;
typedef struct _FilterStatisticsType *PFilterStatistics;

enum eGevStreamFlags
{
	GotLeader				= 0x00000001,
	GotTrailer				= 0x00000002,
	ValidLeader				= 0x00000004,
	ValidTrailer			= 0x00000008,
	DataComplete			= 0x00000010,
	DidRequestResend	= 0x00001000,
	WasError				= 0x80000000,
	ErrPackBitFieldOverrun  = WasError | 0x00010000,
	ErrPayloadBufferOverrun = WasError | 0x00020000,
	ErrLeaderBufferOverrun  = WasError | 0x00040000,
	ErrTrailerBufferOverrun = WasError | 0x00080000,
	ErrTimedOut             = WasError | 0x00100000,
	ErrShortPacket          = WasError | 0x00400000,
	ErrInvalidPacketId      = WasError | 0x00800000,
};

enum eDebugFlags
{
	edfPrintQueue			= 0x00000001,
	edfPrintIOCtrl			= 0x00000002,
	edfPrintRead			= 0x00000004,
	edfPrintStartIo			= 0x00000008,
	edfPrintCompleteIo		= 0x00000010,
	edfPrintPacketRxBasic	= 0x00000020,
	edfPrintPacketRxAdv		= 0x00000040,
	edfRESERVED_0x00000080	= 0x00000080,
	edfPrintActiveCancel	= 0x00000100,
	edfPrintQueueCancel		= 0x00000200,
	edfRESERVED_0x00000400	= 0x00000400,
	edfRESERVED_0x00000800	= 0x00000800,
	edfPrintToTimer			= 0x00001000,
	edfRESERVED_0x00002000	= 0x00002000,
	edfRESERVED_0x00004000	= 0x00004000,
	edfRESERVED_0x00008000	= 0x00008000,
	edfPrintGotLeader		= 0x00010000,
	edfPrintGotTrailer		= 0x00020000,
	edfPrintGotPayload		= 0x00040000,
	edfPrintSkipped			= 0x00080000,
	edfPrintBitfield		= 0x00100000,
	edfPrintResend			= 0x00200000,
	edfPrintResendDetail	= 0x00400000,
	edfPrintResendGapTooBig	= 0x00800000,
	edfPrintMdl				= 0x01000000,
	edfRESERVED_0x02000000	= 0x02000000,
	edfRESERVED_0x04000000	= 0x04000000,
	edfRESERVED_0x08000000	= 0x08000000,
	edfRESERVED_0x10000000	= 0x10000000,
	edfRESERVED_0x20000000	= 0x20000000,
	edfRESERVED_0x40000000	= 0x40000000,
	edfRESERVED_0x80000000	= 0x80000000
};

struct _GevMemBlock
{
	// Size of Block in Bytes
	uint64_t SizeBytes;
	// Offset of Block in Bytes, beginning from Buffer start
	uint64_t OffsetBytes;
};
typedef struct _GevMemBlock GevMemBlock;

#define BUFFER_MAGIC 0x4d56600D

struct _GevDataRequest
{
	uint64_t pHandle;
	//*******Input
	// Check for correctly initialized struct
	uint64_t Magic;
	// struct_size, to check for compatibility
	uint64_t StructSize;
	// total size of provided buffer including struct + data fields
	uint64_t UsermodePayloadBufferPtr;
	// User Virtual Buffer size
	uint64_t UsermodePayloadBufferSize;
	// Defines a Timeout in Timeout-Timer-Ticks
	// After Timeout ticks with no activity on the current irp it will be timed out
	uint64_t Timeout;
	// Leader Block definition
	GevMemBlock Leader;
	// Trailer Block definition
	GevMemBlock Trailer;
	// Bitfield Block definition
	GevMemBlock PacketBitfield;
	// size of a full payload packet
	uint64_t PayloadSize;
	// space for future extension
	uint64_t in_spare[4];
	//*******Output
	// Block ID : this is the sequence Number for the current data block. It stays
	// unchanged for all packets belonging to this block
	uint64_t BlockId; 
	// counter for received packets, double rx packets are not counted
	// this is for a fast completeness check
	uint64_t RxPacketCounter;
	// Flags see eGevStreamFlags
	uint64_t ResultFlags;
	// Data space
	// char DataSpace[4096];
};
typedef struct _GevDataRequest GevDataRequest;
typedef struct _GevDataRequest *PGevDataRequest;

struct ioctl_object {
	uint8_t banknum;
	uint64_t value;
};
typedef struct ioctl_object IoCtlObj;
typedef struct ioctl_object *PIoCtlObj;

struct _FilterAnalyzerInfo {
	uint32_t FilterIP;
	uint32_t FilterPort;
	uint32_t PacketSize;
	uint32_t ClientIP;
	uint32_t ClientPort;
};
typedef struct _FilterAnalyzerInfo FilterAnalyzerInfo;
typedef struct _FilterAnalyzerInfo *PFilterAnalyzerInfo;

#endif /*__COMMONLIN_H__*/
