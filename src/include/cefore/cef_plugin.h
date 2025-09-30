/*
 * Copyright (c) 2016-2023, National Institute of Information and Communications
 * Technology (NICT). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the NICT nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NICT AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE NICT OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * cef_plugin.h
 */

#ifndef __CEF_PLUGIN_HEADER__
#define __CEF_PLUGIN_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#include <cefore/cef_rngque.h>
#include <cefore/cef_mpool.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_hash.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_pit.h>
#include <cefore/cef_face.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/*---------------------------------------------------------
	Common
-----------------------------------------------------------*/

/***** level of logging 		*****/
#define CefT_Log_None 			0x0000			/* OFF 									*/
#define CefT_Log_General		0x0001			/* General Information for User 		*/
#define CefT_Log_Debug			0x0003			/* Debug Information for Developer 		*/
												/* and CefT_Log_General					*/

/***** upper limit values 		*****/
#define CefC_Elem_Face_Num				32

/***** type of queue entry 		*****/
#define CefC_Elem_Type_Invalid 			0x00
#define CefC_Elem_Type_Interest 		0x01
#define CefC_Elem_Type_Object 			0x02
#define CefC_Elem_Type_Del_PIT 			0x04

/*---------------------------------------------------------
	Transport
-----------------------------------------------------------*/

/****** TLVs for use in the CefC_T_OPT_TRANSPORT TLV *****/
#define CefC_T_OPT_TP_NONE				0x0000		/* Invalid 							*/
#define CefC_T_OPT_TP_SAMPTP			0x0001		/* Sample Transport 				*/
#define CefC_T_OPT_TP_L4C2				0x0002		/* L4C2 							*/
#define CefC_T_OPT_TP_FWDTP 			0x0003		/* forwarding strategy prototype	*/
#define CefC_T_OPT_TP_L2MCTP			0x0004		/* Low-Latency MuliCast Transport	*/
#define CefC_T_OPT_TP_ARTEMISTP			0x0005		/* Fast Recovery Transport			*/
#define CefC_T_OPT_TP_NUM				0x0006

/*---------------------------------------------------------
	Common
-----------------------------------------------------------*/

/***** Request to cefnetd 		*****/
#define CefC_Pi_Interest_Send 			0x0001
#define CefC_Pi_Interest_NoSend 		0x0002
#define CefC_Pi_Object_Send 			0x0004
#define CefC_Pi_Object_NoSend 			0x0008
#define CefC_Pi_Object_Match 			0x0010
#define CefC_Pi_All_Permission 			0x0015

/*---------------------------------------------------------
	Forwarding Strategy Plugin
-----------------------------------------------------------*/
#define CefC_FwdStrPlg_Max_NameLen		64


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/*---------------------------------------------------------
	Common
-----------------------------------------------------------*/

/***** element of parameters list 			*****/
typedef struct _CefT_List_Elem {
	struct _CefT_List_Elem*		prev;			/* pointer to the previous element 		*/
	struct _CefT_List_Elem*		next;			/* pointer to the next element 			*/
	void*						elem_ptr;		/* pointer to the listed data 			*/
} CefT_List_Elem;

/***** structure of parameters list 					*****/
typedef struct _CefT_List {
	unsigned int 			size;				/* size of parameters list 				*/
	CefT_List_Elem*			head_ptr;			/* pointer to the head element 			*/
	CefT_List_Elem*			tail_ptr;			/* pointer to the tail element 			*/
} CefT_List;

/***** store the values of one parameter 	*****/
typedef struct plugin_param {

	char 					param[33];			/* name of parameter 					*/
	CefT_List* 				values;				/* values of this parameter 			*/
	struct plugin_param* 	next;				/* pointer to next parameter 			*/
} CefT_Plugin_Param;

/***** store the parameters of one tag 	*****/
typedef struct plugin_tag {

	char 					tag[33];			/* name of tag 							*/
	CefT_Plugin_Param		params;				/* parameters of this tag 				*/
	struct plugin_tag* 		next;				/* pointer to next tag 					*/
	int 					num;

} CefT_Plugin_Tag;


/***** Data of Rx Queue Element for Interest/Object 	*****/
typedef struct {

	int 					plugin_variant;			/* plugin variant 					*/
	int 					type;					/* CefC_Elem_Type_XXX 				*/
	uint32_t 				hashv;					/* Hash value 						*/
	uint16_t 				in_faceid;				/* FaceID that the message arrived 	*/
	CefT_CcnMsg_MsgBdy* 	parsed_msg;				/* parsed message information 		*/
	CefT_CcnMsg_OptHdr*		parsed_oph;				/* parsed option header				*/
	unsigned char			ophdr[CefC_Max_Header_Size];
													/* value field in hop-by-hop option */
													/* header relating to this plugin	*/
													/* valiant 							*/
	uint16_t 				ophdr_len;				/* length of ophder value field 	*/
	unsigned char			msg[CefC_Max_Msg_Size];
													/* message 							*/
	uint16_t 				msg_len;				/* length of the message 			*/
	uint16_t 				out_faceids[CefC_Elem_Face_Num];
													/* outgoing FaceIDs that were 		*/
													/* searched from PIT/FIB 			*/
	int						out_faceid_num;			/* number of outgoing FaceID		*/
	double					bw_utilization;			/* in-NIC bandwidth utilization		*/

} CefT_Rx_Elem;

/***** Data of Rx Queue Element for Signal to delete PIT entry 	*****/
typedef struct {

	uint32_t 	hashv;								/* Hash value 						*/
	uint16_t 	faceids[CefC_Elem_Face_Num];		/* FaceIDs to delete 				*/
	int			faceid_num;							/* number of outgoing FaceID		*/

} CefT_Rx_Elem_Sig_DelPit;

/***** Data of Tx Queue Element for Interest/Object 	*****/
typedef struct {

	int 			type;							/* CefC_Elem_Type_XXX 				*/
	unsigned char	msg[CefC_Max_Msg_Size]; 		/* message 							*/

	uint16_t 		msg_len;						/* length of the message 			*/
	uint16_t 		faceids[CefC_Elem_Face_Num];	/* outgoing FaceIDs that were 		*/
													/* searched from PIT/FIB 			*/
	int				faceid_num;						/* number of outgoing FaceID		*/

} CefT_Tx_Elem;


/*---------------------------------------------------------
	Transport
-----------------------------------------------------------*/

typedef struct _CefT_Plugin_Tp {

	/*** transport variant 							***/
	int 			variant;

	/*** callback to init the transport plugin 		***/
	int (*init)(struct _CefT_Plugin_Tp*, void*);

	/*** callback to process the received cob		***/
	int (*cob)(struct _CefT_Plugin_Tp*, CefT_Rx_Elem*);

	/*** callback to process the received cob from cs	***/
	int (*cob_from_cs)(struct _CefT_Plugin_Tp*, CefT_Rx_Elem*);

	/*** callback to process the received interest	***/
	int (*interest)(struct _CefT_Plugin_Tp*, CefT_Rx_Elem*);

	/*** callback to signal the PIT entries delete	***/
	void (*pit)(struct _CefT_Plugin_Tp*, CefT_Rx_Elem_Sig_DelPit*);

	/*** callback to post process					***/
	void (*destroy)(struct _CefT_Plugin_Tp*);

	/*** tx queue 									***/
	CefT_Rngque			*tx_que;
	CefT_Rngque			*tx_que_high, *tx_que_low;
	CefT_Mp_Handle 		tx_que_mp;

} CefT_Plugin_Tp;

/*---------------------------------------------------------
	Cache Policy
-----------------------------------------------------------*/

typedef struct _CefT_Plugin_Cp {

	/*** cache policy variant 						***/
	int 			variant;

} CefT_Plugin_Cp;

/*---------------------------------------------------------
	EFI
-----------------------------------------------------------*/

typedef struct _CefT_Plugin_Efi {

	/*** EFI variant 								***/
	int 			variant;

} CefT_Plugin_Efi;

/*---------------------------------------------------------
	Mobility
-----------------------------------------------------------*/

typedef struct _CefT_Plugin_Mb {

	/*** callback to init the mobility plugin 		***/
	int (*init)(struct _CefT_Plugin_Mb*, const CefT_Rtts*, void**);

	/*** callback to process the received cob		***/
	int (*cob)(struct _CefT_Plugin_Mb*, CefT_Rx_Elem*);

	/*** callback to process the received interest	***/
	int (*interest)(struct _CefT_Plugin_Mb*, CefT_Rx_Elem*);

	/*** callback to post process					***/
	void (*destroy)(struct _CefT_Plugin_Mb*);

	/*** tx queue 									***/
	CefT_Rngque* 		tx_que;
	CefT_Mp_Handle 		tx_que_mp;

	/*** Neighbor Management						***/
	int 				face_num;					/* Number of RTT record table 		*/
	uint32_t 			rtt_interval;				/* Interval of measuring RTT[ms]	*/

} CefT_Plugin_Mb;

/*---------------------------------------------------------
	Plugin Manager which cefnetd uses
-----------------------------------------------------------*/
typedef struct {

	CefT_Plugin_Tp* 	tp;							/* Transport Plugin 				*/
	CefT_Plugin_Cp* 	cp;							/* Cache Policy Plugin 				*/
	CefT_Plugin_Efi* 	efi;						/* EFI Plugin 						*/
	CefT_Plugin_Mb* 	mb;							/* Mobility Plugin 					*/
//	CefT_Rngque* 		tx_que;						/* TX ring buffer 					*/
//	CefT_Mp_Handle 		tx_que_mp;					/* Memory Pool for CefT_Tx_Elem 	*/

} CefT_Plugin_Handle;

//0.8.3
/*---------------------------------------------------------
	Plugin Interface for libcefnetd_plugin
-----------------------------------------------------------*/
typedef struct _CefT_Plugin_Bw_Stat {
	/* Initialize process */
	int (*init)(int congestion_threshold);

	/* Destroy process */
	void (*destroy)(void);

	/* Congestion status get */
	double (*stat_get)(int if_idx);

	/* Get Table Index */
	int (*stat_tbl_index_get)(char* ip_str);
} CefT_Plugin_Bw_Stat;

#if 0
typedef struct CefnetdT_Plugin_Interface {
	/* Bandwidth Stat Interface */
	CefT_Plugin_Bw_Stat*	bw_stat_if;

} CefnetdT_Plugin_Interface;
#endif

/*---------------------------------------------------------
	Forwarding Strategy Plugin
-----------------------------------------------------------*/
typedef struct CefT_FwdStrtgy_Param {
	void*					hdl_cefnetd;

	uint16_t*				faceids;			/* I/C  */
	uint16_t				faceid_num;			/* I/C  */
	int						peer_faceid;		/* I    */
	unsigned char*			msg;				/* I/C  */
	uint16_t				payload_len;		/* I/C  */
	uint16_t				header_len;			/* I/C  */
	CefT_CcnMsg_MsgBdy		*pm;				/* I/C  */
	CefT_CcnMsg_OptHdr		*poh;				/* I/C  */
	CefT_Pit_Entry*			pe;					/* I/C  */
	CefT_Pit_Entry*			pe_refer;			/* I    */
	CefT_Fib_Entry*			fe;					/* I/C  */

	uint64_t*				cnt_send_frames;	/* I/C: Pointer of variable in Cefnetd handle              */
												/*      for Count the number of frames sent in the Plugin. */
												/*      "Tx Interest" or "Tx ContentObject"                */
	uint64_t*				cnt_send_types;		/* I  : Count by Interest type */

} CefT_FwdStrtgy_Param;

typedef struct _CefT_Plugin_Fwd_Strtgy {
	/* Initialize process */
	int (*init)(void);

	/* Destroy process */
	void (*destroy)(void);

	/* Forward Interest */
	void (*fwd_int)(CefT_FwdStrtgy_Param* fwdstr);

	/* Forward ContentObject */
	void (*fwd_cob)(CefT_FwdStrtgy_Param* fwdstr);

	/* Update In-band Network Telemetry */
	void (*fwd_telemetry)(CefT_FwdStrtgy_Param* fwdstr);

} CefT_Plugin_Fwd_Strtgy;


/****************************************************************************************
	Function declaration
 ****************************************************************************************/

/*=======================================================================================
	Common
 =======================================================================================*/

/*--------------------------------------------------------------------------------------
	Inits plugin
----------------------------------------------------------------------------------------*/
int
cef_plugin_init (
	CefT_Plugin_Handle* plgin_hdl					/* plugin handle 					*/
);
/*--------------------------------------------------------------------------------------
	Destroy plugin
----------------------------------------------------------------------------------------*/
int
cef_plugin_destroy (
	CefT_Plugin_Handle* plgin_hdl					/* plugin handle 					*/
);
/*--------------------------------------------------------------------------------------
	Gets values of specified tag and parameters
----------------------------------------------------------------------------------------*/
CefT_List* 											/* listed parameters 				*/
cef_plugin_parameter_value_get (
	const char* tag, 								/* tag 								*/
	const char* parameter							/* parameter 						*/
);
/*--------------------------------------------------------------------------------------
	Gets the size of the specified list
----------------------------------------------------------------------------------------*/
int 												/* size of the specified list 		*/
cef_plugin_list_size (
	CefT_List* list_ptr								/* list pointer 					*/
);
/*--------------------------------------------------------------------------------------
	Gets the stored data which is listed in the specified position
----------------------------------------------------------------------------------------*/
void* 												/* pointer to the data which is 	*/
													/* listed in the specified position */
cef_plugin_list_access (
	CefT_List* list_ptr,							/* list pointer 					*/
	int pos_index									/* position in the list to access 	*/
);
/*--------------------------------------------------------------------------------------
	Gets informations of specified tag
----------------------------------------------------------------------------------------*/
CefT_Plugin_Tag* 									/* tag informations					*/
cef_plugin_tag_get (
	const char* tag 								/* tag 								*/
);


/*=======================================================================================
	Transport
 =======================================================================================*/

/*--------------------------------------------------------------------------------------
	Inits Transport Plugin
----------------------------------------------------------------------------------------*/
int 												/* size of the specified list 		*/
cef_tp_plugin_init (
	CefT_Plugin_Tp** 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rngque			*tx_que,					/* TX ring buffer 					*/
	CefT_Rngque 		*tx_que_high,				/* TX ring buffer 					*/
	CefT_Rngque 		*tx_que_low,				/* TX ring buffer 					*/
	CefT_Mp_Handle 		tx_que_mp,					/* Memory Pool for CefT_Tx_Elem 	*/
	void* 				arg_ptr						/* Input argment block  			*/
);
/*--------------------------------------------------------------------------------------
	Post process for Transport Plugin
----------------------------------------------------------------------------------------*/
void
cef_tp_plugin_destroy (
	CefT_Plugin_Tp* 	tp 							/* Transport Plugin Handle			*/
);

/*=======================================================================================
	Mobility
 =======================================================================================*/

/*--------------------------------------------------------------------------------------
	Inits Mobility Plugin
----------------------------------------------------------------------------------------*/
int 												/* variant caused the problem		*/
cef_mb_plugin_init (
	CefT_Plugin_Mb** 	mb, 						/* Mobility Plugin Handle			*/
	CefT_Rngque* 		tx_que,						/* TX ring buffer 					*/
	CefT_Mp_Handle 		tx_que_mp,					/* Memory Pool for CefT_Tx_Elem 	*/
	const CefT_Rtts* 	rtt_tbl,					/* RTT record table (read only) 	*/
	int 				face_num,					/* Number of RTT record table 		*/
	uint32_t 			rtt_interval, 				/* Interval of measuring RTT[ms]	*/
	void** 				vret 						/* return to the allocated info 	*/
);

/*--------------------------------------------------------------------------------------
	Post process for Mobility Plugin
----------------------------------------------------------------------------------------*/
void
cef_mb_plugin_destroy (
	CefT_Plugin_Mb* 	mv 							/* Mobility Plugin Handle			*/
);

/*=======================================================================================
	Common
 =======================================================================================*/

/*--------------------------------------------------------------------------------------
	Reads the plugin.conf and stores values as the string
----------------------------------------------------------------------------------------*/
void
cef_plugin_config_read (
	void
);

/*--------------------------------------------------------------------------------------
	Outputs log
----------------------------------------------------------------------------------------*/
void
cef_plugin_log_write (
	uint16_t log_level,
	const char* plugin,
	const char* log
);

/*=======================================================================================
	cefnetd built-in APIs
 =======================================================================================*/
/*--------------------------------------------------------------------------------------
	Forward Interest API
----------------------------------------------------------------------------------------*/
void
cef_forward_interest (
	CefT_FwdStrtgy_Param* fwdstr
);

/*--------------------------------------------------------------------------------------
	Forward ContentObject API
----------------------------------------------------------------------------------------*/
void
cef_forward_object (
	CefT_FwdStrtgy_Param* fwdstr
);
/*--------------------------------------------------------------------------------------
	Forward CcninfoReq API
----------------------------------------------------------------------------------------*/
void
cef_forward_ccninforeq (
	CefT_FwdStrtgy_Param* fwdstr,
	int fdcv_authNZ,
	uint32_t fdcv_f
);

/*--------------------------------------------------------------------------------------
	Handles the elements of TX queue
----------------------------------------------------------------------------------------*/
void *
cefnetd_cefstatus_thread (
	void *p									/* cefnetd handle							*/
);

void
cefnetd_frame_send_txque_faces (
	void*			hdl,					/* cefnetd handle							*/
	uint16_t 		faceid_num, 			/* number of Face-ID				 		*/
	uint16_t 		faceid[], 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);

void
cefnetd_frame_send_txque (
	void*			hdl,					/* cefnetd handle							*/
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);

long
cefnetd_transmit_packet_interval (
	  uint16_t				faceid,								 /* Face-ID indicating the destination				*/
	  long					tv_usec
);

#endif // __CEF_PLUGIN_HEADER__
