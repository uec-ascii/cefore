#ifndef __CEF_CONTENTVERIFICATION_HEADER__
#define __CEF_CONTENTVERIFICATION_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <cefore/cef_plugin.h>

/****************************************************************************************
 Function Declaration
 ****************************************************************************************/

int
cef_plugin_cotentverification_init (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	void* 				arg_ptr						/* Input argment block  			*/
);

int
cef_plugin_cotentverification_cob (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
);

int
cef_plugin_cotentverification_interest (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
);

void
cef_plugin_cotentverification_delpit (
	CefT_Plugin_Tp* 			tp, 				/* Transport Plugin Handle			*/
	CefT_Rx_Elem_Sig_DelPit* 	info
);

void
cef_plugin_cotentverification_destroy (
	CefT_Plugin_Tp* 	tp 							/* Transport Plugin Handle			*/
);

#endif // __CEF_CONTENTVERIFICATION_HEADER__
