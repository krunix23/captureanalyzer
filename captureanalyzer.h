
#ifndef _CAPTUREANALYZER_H_
#define _CAPTUREANALYZER_H_

using namespace std;

/**
 * @short Application Main Window
 * @author Kruno Mrak <kruno.mrak@matrix-vision.de>
 * @version 0.1
 */

class CaptureSplitterWindow;

struct _Statistics {
	struct _IPv4AddrStats IPv4Stat;
	struct _FilterStatisticsType FiltStat;
	struct _ResendStatisticsType ResendStat;
};

class 
CaptureAnalyzerapp : public wxApp
{
	public:
		virtual bool OnInit();
};

class 
CaptureAnalyzerFrame : public wxFrame
{
	public:
		CaptureAnalyzerFrame( const wxString& title, const wxPoint& pos, const wxSize& size );
		~CaptureAnalyzerFrame( void );
		void OnAbout( wxCommandEvent& event );
		void OnQuit( wxCommandEvent& event );
		void OnAdapterComboTextChanged( wxCommandEvent& event );
		void OnListDevices( wxCommandEvent& e );
		void OnToggleStatisticsUpdate( wxCommandEvent& event );
		void OnTimer( wxTimerEvent& e );
		void OnBtnResetAdapterStatistics( wxCommandEvent& event );
		void OnBtnResetResendStatistics( wxCommandEvent& event );
		void OnBtnResetFilterStatistics( wxCommandEvent& event );
		void OnListDeleteAllItems( wxListEvent& );
		void OnListSelected( wxListEvent& e );
		void OnListDeselected( wxListEvent& e );

	private:
		DECLARE_EVENT_TABLE()
	
		int						m_fd;
		uint32_t 			*m_pDeviceList;
		bool boGotAdapterStatistics;
		bool boGotResendStatistics;
		bool boGotFilterStatistics;
		struct ioctl_object m_io;
		struct _Statistics m_stats;

		CaptureSplitterWindow* m_splitter;
		CaptureSplitterWindow* m_splitter2;

		wxToolBar*							m_pToolBar;
		wxSplitterWindow*				m_pUpperSplitter;
		wxSplitterWindow*				m_pLowerSplitter;
		wxComboBox*							m_pAdapterCombo;
		wxBoxSizer*							m_SelectedAdapter;
		wxNotebook*							m_pNotebook;
		wxTextCtrl*							m_pLogWindow;
		wxListCtrl*							m_pFilterListCtrl;
		wxTextCtrl*							m_pLogWindow2;

		wxBoxSizer*							m_FilterData;
		wxButton*								m_pBTNResetAdapterStatistics;
		wxButton*								m_pBTNResetResendStatistics;
		wxButton*								m_pBTNResetFilterStatistics;
		wxStaticText*						m_pSTPacketsThroughMPSendPackets;
		wxStaticText*						m_pSTPacketsDroppedInMPSendPackets;
		wxStaticText*						m_pSTPacketsThroughPTReceive;
		wxStaticText*						m_pSTPacketsDroppedInPTReceive;
		wxStaticText*						m_pSTPacketsThroughPTReceivePacket;
		wxStaticText*						m_pSTPacketsDroppedInPtReceivePacket;
		wxStaticText*						m_pSTPacketBytesCopiedCount;
		wxStaticText*						m_pSTPacketsDroppedByPacketDropper;
		wxStaticText*						m_pSTResendCmdsIssued;
		wxStaticText*						m_pSTReRequestedPackets;
		wxStaticText*						m_pSTRecoveredPackets;
		wxStaticText*						m_pSTSingleGapsDetected;
		wxStaticText*						m_pSTMultiGapsDetected;
		wxStaticText*						m_pSTLargestGapSize;
		wxStaticText*						m_pSTAnnouncedBuffers;
		wxStaticText*						m_pSTBuffersInQueue;
		wxStaticText*						m_pSTBuffersQueued;
		wxStaticText*						m_pSTBuffersCanceled;
		wxStaticText*						m_pSTBuffersTimedOut;
		wxStaticText*						m_pSTBuffersSuccessfullyReturned;
		wxStaticText*						m_pSTBuffersWithUnknownError;
		wxStaticText*						m_pSTInvalidIO;
		wxStaticText*						m_pSTMissingLeaders;
		wxStaticText*						m_pSTMissingTrailers;
		wxStaticText*						m_pSTMissingPayloadPackets;
		wxStaticText*						m_pSTCompleteFrameCnt;
		wxStaticText*						m_pSTIncompleteFrameCnt;
		wxStaticText*						m_pSTFaultyImages;
		wxStaticText*						m_pSTReconstructedFrames;
		wxStaticText*						m_pSTUnsuccessfullyReconstructedFrames;
		wxStaticText*						m_pSTLostFrames;
		wxStaticText*						m_pSTDroppedLeaders;
		wxStaticText*						m_pSTDroppedTrailers;
		wxStaticText*						m_pSTDroppedPayload;
		wxStaticText*						m_pSTDuplicatePacket;
		wxStaticText*						m_pSTDroppedUnknown;
		wxStaticText*						m_pSTProcessedLeaders;
		wxStaticText*						m_pSTProcessedTrailers;
		wxStaticText*						m_pSTProcessedPayload;
		wxStaticText*						m_pSTProcessedUnknown;

		static const wxTextAttr	m_ERROR_STYLE;
		static const wxTextAttr	m_MSG_STYLE;
		const wxString					m_NoItemString;
		wxMenuItem*							m_pMIAction_UpdateStatistics;
		wxTimer									m_ListUpdateTimer;
		wxMutex*								m_pIoctlMutex;
	
// 		map<std::string,uint32_t> DeviceList;
		map<wxString,uint32_t>::iterator it_DevList;
		map<wxString,uint32_t> DeviceList;

		wxString								m_FilterIP;
		wxString								m_FilterPort;
		wxString								m_PacketSize;
		wxString								m_ClientIP;
		wxString								m_ClientPort;

		void OpenFilter( void );
		void BuildDeviceList ( void );
		void DrvBindFilter( void );
		void SetupUpdateTimer( bool boActive );
		void DrvQueryStatistics( void );
		void UpdateStatistics( struct _Statistics* stats );
		void UpdateDlgControls( void );
		void WriteLogMessage( const wxString& msg, const wxTextAttr& style /* = wxTextAttr(wxColour(0, 0, 0)) */ );
		void GetFilterInfo( void );
	
		enum TTimerEvent
		{
			teListUpdate
		};
		enum
		{
			TIMER_PERIOD = 1000
		};
	
		enum TMenuItem
		{
			miQuit = 1,
			miAbout,
			miAction_UpdateStatistics,
			tbAction_UpdateStatistics,
			miAction_ConfigureDebugOutput,
			miAction_ListDevices,
			tbAction_ListDevices,
		};
	
		enum TWidgetIDs
		{
			widUpperSplitter = 1,
			widLowerSplitter,
			widAdapterCombo,
			widTotalPacketCount,
			widBtnResetAdapterStatistics,
			widBtnResetResendStatistics,
			widBtnSendTestPacket,
			widBtnResetFilterStatistics,
			widBtnApplyResendParameters,
			widBtnEnableResendTestParameters,
			widBtnDisableResendTestParameters,
			widCBEditResendParameters,
			widBtnApplyAdapterSpecificTestsParameters,
			widCBPacketDropActive,
			LIST_CTRL 
		};

		enum TListColumn
		//-----------------------------------------------------------------------------
		{
// 			lcAdapterFilterIndex,
			lcFilterIPAddress,
			lcFilterPort,
			lcFilterPacketSize,
// 			lcFilterActive,
			lcGVCPClientPort,
			lcClientIP,
// 			lcGVCPStreamChannelIndex,
			lcLAST_COLUMN
		};
};

class CaptureSplitterWindow : public wxSplitterWindow
{
public:
    CaptureSplitterWindow(wxFrame *parent);

    // event handlers
//     void OnPositionChanged(wxSplitterEvent& event);
//     void OnPositionChanging(wxSplitterEvent& event);
//     void OnDClick(wxSplitterEvent& event);
//     void OnUnsplitEvent(wxSplitterEvent& event);

private:
    wxFrame *m_frame;

    DECLARE_EVENT_TABLE()
    DECLARE_NO_COPY_CLASS(CaptureSplitterWindow)
};

enum
{
	Menu_File_Quit = 100,
	Menu_File_About
};

#endif // _CAPTUREANALYZER_H_
