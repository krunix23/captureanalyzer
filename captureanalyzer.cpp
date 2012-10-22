#include <wx/wx.h>
#include <wx/string.h>
#include <wx/notebook.h>
#include <wx/thread.h>
#include <wx/splitter.h>
#include <wx/listctrl.h>

#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <iostream>
#include <map>

#include "commonlin.h"
#include "captureanalyzer.h"
#include "icons.h"
#include "mvIcon.xpm"

using namespace std;

BEGIN_EVENT_TABLE( CaptureAnalyzerFrame, wxFrame )
	EVT_MENU( Menu_File_Quit, CaptureAnalyzerFrame::OnQuit )
	EVT_MENU( Menu_File_About, CaptureAnalyzerFrame::OnAbout )
	EVT_MENU( miAction_UpdateStatistics, CaptureAnalyzerFrame::OnToggleStatisticsUpdate )
	EVT_MENU( miAction_ListDevices, CaptureAnalyzerFrame::OnListDevices )
	EVT_TEXT( widAdapterCombo, CaptureAnalyzerFrame::OnAdapterComboTextChanged )
	EVT_MENU( tbAction_ListDevices, CaptureAnalyzerFrame::OnListDevices)
	EVT_MENU( tbAction_UpdateStatistics, CaptureAnalyzerFrame::OnToggleStatisticsUpdate)
	EVT_BUTTON( widBtnResetAdapterStatistics, CaptureAnalyzerFrame::OnBtnResetAdapterStatistics)
	EVT_BUTTON(widBtnResetResendStatistics, CaptureAnalyzerFrame::OnBtnResetResendStatistics)
	EVT_BUTTON( widBtnResetFilterStatistics, CaptureAnalyzerFrame::OnBtnResetFilterStatistics)
	EVT_TIMER(wxID_ANY, CaptureAnalyzerFrame::OnTimer)
	EVT_LIST_DELETE_ALL_ITEMS(LIST_CTRL, CaptureAnalyzerFrame::OnListDeleteAllItems)
	EVT_LIST_ITEM_SELECTED(LIST_CTRL, CaptureAnalyzerFrame::OnListSelected)
	EVT_LIST_ITEM_DESELECTED(LIST_CTRL, CaptureAnalyzerFrame::OnListDeselected)
END_EVENT_TABLE()

IMPLEMENT_APP(CaptureAnalyzerapp)

wxString ConvertIntToIpv4wxString( uint32_t ipv4 )
{
	wxString ipv4str;

	ipv4str.Printf(wxT("%d.%d.%d.%d"), ((ipv4 & 0xff000000)>>24), ((ipv4 & 0x00ff0000)>>16), ((ipv4 & 0x0000ff00)>>8), (ipv4 & 0xff) );
	return ipv4str;
}

string ConvertIntToIpv4String( uint32_t ipv4 )
{
	string ipv4str;
	char ipaddr[2];
	if( !ipv4 )
		return 0;

	sprintf(ipaddr,"%d",((ipv4 & 0xff000000)>>24) );
	ipv4str += ipaddr;
	ipv4str += ".";
	sprintf(ipaddr,"%d",((ipv4 & 0x00ff0000)>>16) );
	ipv4str += ipaddr;
	ipv4str += ".";
	sprintf(ipaddr,"%d",((ipv4 & 0x0000ff00)>>8) );
	ipv4str += ipaddr;
	ipv4str += ".";
	sprintf(ipaddr,"%d",(ipv4 & 0xff) );
	ipv4str += ipaddr;
	cout << ipv4str << endl;

	return ipv4str;
}

bool 
CaptureAnalyzerapp::OnInit()
{
	CaptureAnalyzerFrame *frame = new CaptureAnalyzerFrame( wxT( "GigE Vision(tm) Capture Analyzer Linux" ), wxPoint(50,50), wxSize(1000,750) );

	frame->Show(TRUE);
	SetTopWindow(frame);
	return TRUE;
}

const wxTextAttr CaptureAnalyzerFrame::m_ERROR_STYLE(wxColor(255, 0, 0));
const wxTextAttr CaptureAnalyzerFrame::m_MSG_STYLE(wxColor(0, 0, 0));

CaptureAnalyzerFrame::CaptureAnalyzerFrame( const wxString& title, const wxPoint& pos, const wxSize& size )
	: wxFrame((wxFrame *)NULL, -1, title, pos, size ), m_NoItemString(wxT("No Filter active"))
{
	m_fd = 0;
	memset( &m_stats, 0x00, sizeof( struct _Statistics ) );
	wxMenu *menuFile = new wxMenu;
	
	menuFile->Append( miAction_ListDevices, wxT( "&List &Devices\tCTRL+D" ) );
	m_pMIAction_UpdateStatistics = menuFile->Append( miAction_UpdateStatistics, wxT( "&Update Statistics\tCTRL+U" ) );
	menuFile->Append( Menu_File_About, wxT( "&About..." ) );
	menuFile->AppendSeparator();
	menuFile->Append( Menu_File_Quit, wxT( "E&xit" ) );
	
	wxMenuBar *menuBar = new wxMenuBar;
	menuBar->Append( menuFile, wxT( "&File" ) );
	
	SetMenuBar( menuBar );

	// define the applications icon
	wxIcon icon(mvIcon_xpm);
	SetIcon( icon );

	wxPanel* pPanel = new wxPanel(this);
// 	wxFrame* pFrame = new wxFrame(this);

	m_pToolBar = CreateToolBar( wxNO_BORDER | wxHORIZONTAL | wxTB_FLAT | wxTB_TEXT );
	m_pToolBar->SetMargins( 5, 5 );
	m_pToolBar->SetToolBitmapSize( wxSize(32, 16) );
	m_pToolBar->SetToolSeparation( 10 );

	wxStaticText *pStaticText = new wxStaticText(m_pToolBar, -1, wxT("  IP address  "));
	m_pToolBar->AddControl( pStaticText );

	m_pAdapterCombo = new wxComboBox( m_pToolBar, widAdapterCombo, m_NoItemString, wxDefaultPosition, wxSize(150,wxDefaultCoord), 0, NULL, wxCB_DROPDOWN | wxCB_READONLY );
	m_pAdapterCombo->Select( 0 );
	m_pAdapterCombo->SetToolTip( wxT("Contains a list of detected network adapters") );
	m_pToolBar->AddControl( m_pAdapterCombo );
	m_pToolBar->AddSeparator();
	m_pToolBar->AddTool( tbAction_ListDevices, wxT("List Devices"), list_xpm, wxNullBitmap, wxITEM_NORMAL, wxT("lists active filter"), wxT("lists active filter") );
	m_pToolBar->AddTool( tbAction_UpdateStatistics, wxT("Update Statistics"), DisplayMessages_xpm, wxNullBitmap, /*wxITEM_NORMAL*/ wxITEM_CHECK, wxT("toggles the update of the statistical data"), wxT("toggles the update of the statistical data") );

	m_pToolBar->Realize();

// 	m_splitter2 = new CaptureSplitterWindow(this);
// 	m_splitter2->SetSashGravity(0.0);

	m_pLowerSplitter = new wxSplitterWindow(pPanel, widLowerSplitter, wxDefaultPosition, wxDefaultSize, wxSIMPLE_BORDER );
// 	m_pLowerSplitter->SetMinimumPaneSize( 20 );
// 	m_pLowerSplitter->SetSashGravity( 0.5 );

	m_pUpperSplitter = new wxSplitterWindow(m_pLowerSplitter, widUpperSplitter, wxDefaultPosition, wxDefaultSize, wxSIMPLE_BORDER );
	m_pUpperSplitter->SetMinimumPaneSize( 45 );
// 	m_pUpperSplitter->SetSashGravity( 0.5 );

// 	m_splitter = new CaptureSplitterWindow(m_pLowerSplitter);
// 	m_splitter->SetSashGravity(1.0);

// 	m_pLowerSplitter = new wxSplitterWindow( pPanel, widLowerSplitter, wxDefaultPosition, wxDefaultSize, wxSIMPLE_BORDER );
// 	m_pLowerSplitter->SetMinimumPaneSize( 45 );

	const int GROUPBOX_BORDER_WIDTH_PIXEL = 5;
	const int BTN_BORDER_WIDTH_PIXEL = 4;
// 	const int CHECKBOX_BORDER_PIXEL_WIDTH = 3;

	m_pNotebook = new wxNotebook(/*m_splitter*/ m_pUpperSplitter /*this*/, wxID_ANY);

	wxScrolledWindow* pInformationControlsPage = new wxScrolledWindow( m_pNotebook );
	pInformationControlsPage->SetScrollRate( 10,10 );

	m_pLogWindow = new wxTextCtrl(/*m_splitter*/ m_pLowerSplitter, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxSUNKEN_BORDER | wxTE_RICH | wxTE_READONLY);

// 	m_pLogWindow2 = new wxTextCtrl(m_pUpperSplitter, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxSUNKEN_BORDER | wxTE_RICH | wxTE_READONLY);

	m_pFilterListCtrl = new wxListCtrl(m_pUpperSplitter, LIST_CTRL, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_SINGLE_SEL | wxSUNKEN_BORDER);
// 	m_pFilterListCtrl->SetSize( wxSIZE_AUTO_WIDTH, 10 );

// 	m_pFilterListCtrl->InsertColumn( lcAdapterFilterIndex, wxT("adapter filter index") );
	m_pFilterListCtrl->InsertColumn( lcFilterIPAddress, wxT("filter IP address") );
	m_pFilterListCtrl->InsertColumn( lcFilterPort, wxT("filter port") );
	m_pFilterListCtrl->InsertColumn( lcFilterPacketSize, wxT("filter packet size") );
// 	m_pFilterListCtrl->InsertColumn( lcFilterActive, wxT("filter active") );
	m_pFilterListCtrl->InsertColumn( lcGVCPClientPort, wxT("GVCP client port") );
	m_pFilterListCtrl->InsertColumn( lcClientIP, wxT("client IP address") );
// 	m_pFilterListCtrl->InsertColumn( lcGVCPStreamChannelIndex, wxT("stream channel index") );
	for( unsigned int i=0; i<lcLAST_COLUMN; i++ )
	{
		m_pFilterListCtrl->SetColumnWidth( i, wxLIST_AUTOSIZE_USEHEADER );
	}

//>>>>>>>>>>>>>>>
	wxBoxSizer* pSelectedAdapter = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage , wxT("IPv4Statistics") );
	wxFlexGridSizer* pCurrentAdapterDataGridSizer = new wxFlexGridSizer( 2,0 );
	pCurrentAdapterDataGridSizer->AddGrowableCol( 1,3 );

	// row 1
	pCurrentAdapterDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Packets received: ")), wxSizerFlags().Left() );
	m_pSTPacketsThroughPTReceivePacket = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentAdapterDataGridSizer->Add( m_pSTPacketsThroughPTReceivePacket, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pCurrentAdapterDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Packets dropped: ")), wxSizerFlags().Left() );
	m_pSTPacketsDroppedInPtReceivePacket = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentAdapterDataGridSizer->Add( m_pSTPacketsDroppedInPtReceivePacket, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pCurrentAdapterDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Packets Byte copied[kB]: ")), wxSizerFlags().Left() );
	m_pSTPacketBytesCopiedCount = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentAdapterDataGridSizer->Add( m_pSTPacketBytesCopiedCount, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );

	wxBoxSizer* pAdapterButtonSizer = new wxBoxSizer(wxHORIZONTAL);
	m_pBTNResetAdapterStatistics = new wxButton(pInformationControlsPage, widBtnResetAdapterStatistics, wxT("Reset &Adapter Statistics"));
	pAdapterButtonSizer->Add( m_pBTNResetAdapterStatistics, wxSizerFlags().Right().Border( wxALL, BTN_BORDER_WIDTH_PIXEL ) );

	pSelectedAdapter->Add( pCurrentAdapterDataGridSizer, wxSizerFlags().Align( wxGROW ) );
	pSelectedAdapter->Add( pAdapterButtonSizer, wxSizerFlags().Right().Border( wxALL, BTN_BORDER_WIDTH_PIXEL ) );

//>>>>>>>>>>>>>>>>
// controls for information about the resend related statistics
	wxBoxSizer* pResendStatisticsSizer = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage, wxT("Resend statistics: "));

	// resend information controls
	wxFlexGridSizer* pResendStatisticsGridSizer = new wxFlexGridSizer(2, 0);
	pResendStatisticsGridSizer->AddGrowableCol( 1, 3 );

	// row 1
	pResendStatisticsGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("RESEND_CMDs issued: ")), wxSizerFlags().Left() );
	m_pSTResendCmdsIssued = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pResendStatisticsGridSizer->Add( m_pSTResendCmdsIssued, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pResendStatisticsGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Re-requested packets: ")), wxSizerFlags().Left() );
	m_pSTReRequestedPackets = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pResendStatisticsGridSizer->Add( m_pSTReRequestedPackets, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pResendStatisticsGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Recovered packets: ")), wxSizerFlags().Left() );
	m_pSTRecoveredPackets = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pResendStatisticsGridSizer->Add( m_pSTRecoveredPackets, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );

	wxBoxSizer* pResendStatisticsButtonSizer = new wxBoxSizer(wxHORIZONTAL);
	m_pBTNResetResendStatistics = new wxButton(pInformationControlsPage, widBtnResetResendStatistics, wxT("Reset &Resend Statistics"));
	pResendStatisticsButtonSizer->Add( m_pBTNResetResendStatistics, wxSizerFlags().Right().Border( wxALL, BTN_BORDER_WIDTH_PIXEL ) );

	pResendStatisticsSizer->Add( pResendStatisticsGridSizer, wxSizerFlags().Align( wxGROW ) );
	pResendStatisticsSizer->Add( pResendStatisticsButtonSizer, wxSizerFlags().Right().Border( wxALL, BTN_BORDER_WIDTH_PIXEL ) );

//>>>>>>>>>>>>>>>>
	wxFlexGridSizer* pCurrentFilterBufferDataGridSizer = new wxFlexGridSizer(2, 0);
	pCurrentFilterBufferDataGridSizer->AddGrowableCol( 1, 3 );

	// row 1
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers announced: ")), wxSizerFlags().Left() );
	m_pSTAnnouncedBuffers = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTAnnouncedBuffers, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers in queue: ")), wxSizerFlags().Left() );
	m_pSTBuffersInQueue = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTBuffersInQueue, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers queued: ")), wxSizerFlags().Left() );
	m_pSTBuffersQueued = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTBuffersQueued, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 4
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers canceled: ")), wxSizerFlags().Left() );
	m_pSTBuffersCanceled = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTBuffersCanceled, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 5
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers timed out: ")), wxSizerFlags().Left() );
	m_pSTBuffersTimedOut = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTBuffersTimedOut, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 6
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers successfully returned: ")), wxSizerFlags().Left() );
	m_pSTBuffersSuccessfullyReturned = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTBuffersSuccessfullyReturned, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 7
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Buffers with unknown error: ")), wxSizerFlags().Left() );
	m_pSTBuffersWithUnknownError = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTBuffersWithUnknownError, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 8
	pCurrentFilterBufferDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Invalid IO buffers: ")), wxSizerFlags().Left() );
	m_pSTInvalidIO = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterBufferDataGridSizer->Add( m_pSTInvalidIO, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );

//>>>>>>>>>>>>>>>>
	// filter frame information controls
	wxFlexGridSizer* pProcessedPackets = new wxFlexGridSizer(2, 0);
	pProcessedPackets->AddGrowableCol( 1, 3 );
	// row 1
	pProcessedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Leaders: ")), wxSizerFlags().Left() );
	m_pSTProcessedLeaders = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pProcessedPackets->Add( m_pSTProcessedLeaders, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pProcessedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Trailers: ")), wxSizerFlags().Left() );
	m_pSTProcessedTrailers = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pProcessedPackets->Add( m_pSTProcessedTrailers, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pProcessedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Payload Packets: ")), wxSizerFlags().Left() );
	m_pSTProcessedPayload = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pProcessedPackets->Add( m_pSTProcessedPayload, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );

	// row4
	pProcessedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Duplicate Packets: ")), wxSizerFlags().Left() );
	m_pSTDuplicatePacket = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pProcessedPackets->Add( m_pSTDuplicatePacket, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );

	// row 5
	pProcessedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Unknown Packets: ")), wxSizerFlags().Left() );
	m_pSTProcessedUnknown = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pProcessedPackets->Add( m_pSTProcessedUnknown, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	wxBoxSizer* pCurrentFilterFrameDataProcessedPackets = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage, wxT("Processed Packets: "));
	pCurrentFilterFrameDataProcessedPackets->Add( pProcessedPackets, wxSizerFlags().Align( wxGROW ) );

	wxFlexGridSizer* pDroppedPackets = new wxFlexGridSizer(2, 0);
	pDroppedPackets->AddGrowableCol( 1, 3 );
	// row 1
	pDroppedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Leaders: ")), wxSizerFlags().Left() );
	m_pSTDroppedLeaders = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pDroppedPackets->Add( m_pSTDroppedLeaders, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pDroppedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Trailers: ")), wxSizerFlags().Left() );
	m_pSTDroppedTrailers = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pDroppedPackets->Add( m_pSTDroppedTrailers, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pDroppedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Payload Packets: ")), wxSizerFlags().Left() );
	m_pSTDroppedPayload = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pDroppedPackets->Add( m_pSTDroppedPayload, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 4
	pDroppedPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Unknown Packets: ")), wxSizerFlags().Left() );
	m_pSTDroppedUnknown = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pDroppedPackets->Add( m_pSTDroppedUnknown, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	wxBoxSizer* pCurrentFilterFrameDataDroppedPackets = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage, wxT("Dropped Packets: "));
	pCurrentFilterFrameDataDroppedPackets->Add( pDroppedPackets, wxSizerFlags().Align( wxGROW ) );

	wxFlexGridSizer* pMissingPackets = new wxFlexGridSizer(2, 0);
	pMissingPackets->AddGrowableCol( 1, 3 );
	// row 1
	pMissingPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Leaders: ")), wxSizerFlags().Left() );
	m_pSTMissingLeaders = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pMissingPackets->Add( m_pSTMissingLeaders, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pMissingPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Trailers: ")), wxSizerFlags().Left() );
	m_pSTMissingTrailers = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pMissingPackets->Add( m_pSTMissingTrailers, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pMissingPackets->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Payload packets: ")), wxSizerFlags().Left() );
	m_pSTMissingPayloadPackets = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pMissingPackets->Add( m_pSTMissingPayloadPackets, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	wxBoxSizer* pCurrentFilterFrameDataMissingPackets = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage, wxT("Missing Packets: "));
	pCurrentFilterFrameDataMissingPackets->Add( pMissingPackets, wxSizerFlags().Align( wxGROW ) );

	wxFlexGridSizer* pPackets = new wxFlexGridSizer(3, 0);
	pPackets->AddGrowableCol( 0, 0 );
	pPackets->AddGrowableCol( 1, 0 );
	pPackets->AddGrowableCol( 2, 0 );
	pPackets->Add( pCurrentFilterFrameDataProcessedPackets, wxSizerFlags().Align( wxGROW ).Border( wxALL, GROUPBOX_BORDER_WIDTH_PIXEL ) );
	pPackets->Add( pCurrentFilterFrameDataDroppedPackets, wxSizerFlags().Align( wxGROW ).Border( wxALL, GROUPBOX_BORDER_WIDTH_PIXEL ) );
	pPackets->Add( pCurrentFilterFrameDataMissingPackets, wxSizerFlags().Align( wxGROW ).Border( wxALL, GROUPBOX_BORDER_WIDTH_PIXEL ) );

//>>>>>>>>>>>>>>>>
	wxFlexGridSizer* pCurrentFilterFrameDataGridSizer = new wxFlexGridSizer(2, 0);
	pCurrentFilterFrameDataGridSizer->AddGrowableCol( 1, 3 );
	// row 1
	pCurrentFilterFrameDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Complete frames: ")), wxSizerFlags().Left() );
	m_pSTCompleteFrameCnt = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterFrameDataGridSizer->Add( m_pSTCompleteFrameCnt, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 2
	pCurrentFilterFrameDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Incomplete frames: ")), wxSizerFlags().Left() );
	m_pSTIncompleteFrameCnt = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterFrameDataGridSizer->Add( m_pSTIncompleteFrameCnt, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 3
	pCurrentFilterFrameDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Faulty images: ")), wxSizerFlags().Left() );
	m_pSTFaultyImages = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterFrameDataGridSizer->Add( m_pSTFaultyImages, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 4
	pCurrentFilterFrameDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Reconstructed frames: ")), wxSizerFlags().Left() );
	m_pSTReconstructedFrames = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	m_pSTReconstructedFrames->SetToolTip( wxT("Frames that did arrive with missing packets that have been successfully reconstructed using the resend command") );
	pCurrentFilterFrameDataGridSizer->Add( m_pSTReconstructedFrames, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 5
	pCurrentFilterFrameDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Unsuccessfully reconstructed frames: ")), wxSizerFlags().Left() );
	m_pSTUnsuccessfullyReconstructedFrames = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterFrameDataGridSizer->Add( m_pSTUnsuccessfullyReconstructedFrames, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );
	// row 6
	pCurrentFilterFrameDataGridSizer->Add( new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("Lost frames: ")), wxSizerFlags().Left() );
	m_pSTLostFrames = new wxStaticText(pInformationControlsPage, wxID_ANY, wxT("-"));
	pCurrentFilterFrameDataGridSizer->Add( m_pSTLostFrames, wxSizerFlags(2).Align( wxGROW | wxALIGN_CENTER_VERTICAL ) );

	wxBoxSizer* pFilterButtonSizer = new wxBoxSizer(wxHORIZONTAL);
	m_pBTNResetFilterStatistics = new wxButton(pInformationControlsPage, widBtnResetFilterStatistics, wxT("Reset &Filter Statistics"));
	pFilterButtonSizer->Add( m_pBTNResetFilterStatistics, wxSizerFlags().Right().Border( wxALL, BTN_BORDER_WIDTH_PIXEL ) );

//>>>>>>>>>>>>>>>>
	wxBoxSizer* pCurrentFilterBufferData = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage, wxT("Buffer statistics: "));
	pCurrentFilterBufferData->Add( pCurrentFilterBufferDataGridSizer, wxSizerFlags().Align( wxGROW ) );

	wxBoxSizer* pCurrentFilterFrameData = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage, wxT("Frame statistics: "));
	pCurrentFilterFrameData->Add( pPackets, wxSizerFlags().Align( wxGROW ) );
	pCurrentFilterFrameData->Add( pCurrentFilterFrameDataGridSizer, wxSizerFlags().Align( wxGROW ) );

	wxBoxSizer* pCurrentFilterInfo = new wxBoxSizer(wxVERTICAL);
	pCurrentFilterInfo->Add( pCurrentFilterBufferData, wxSizerFlags().Expand().Align( wxGROW ) );
	pCurrentFilterInfo->Add( pCurrentFilterFrameData, wxSizerFlags().Expand().Align( wxGROW ) );

//>>>>>>>>>>>>>>>
	wxBoxSizer* pFilterData = new wxStaticBoxSizer(wxVERTICAL, pInformationControlsPage , wxT("Selected Filter Data: ") );
	pFilterData->Add( pCurrentFilterInfo, wxSizerFlags().Expand().Border( wxALL, GROUPBOX_BORDER_WIDTH_PIXEL ) );
	pFilterData->Add( pFilterButtonSizer, wxSizerFlags().Right().Border( wxALL, BTN_BORDER_WIDTH_PIXEL ) );

	wxFlexGridSizer* pInformationControlsSizer = new wxFlexGridSizer(2, 0);
	pInformationControlsSizer->AddGrowableCol( 0, 1 );
	pInformationControlsSizer->AddGrowableCol( 1, 2 );
	wxBoxSizer* pLeftHandSideControlsSizer = new wxBoxSizer(wxVERTICAL);
	pLeftHandSideControlsSizer->Add( pSelectedAdapter, wxSizerFlags().Expand().Align( wxGROW ) );
	pLeftHandSideControlsSizer->Add( pResendStatisticsSizer, wxSizerFlags().Expand().Align( wxGROW ) );
	pInformationControlsSizer->Add( pLeftHandSideControlsSizer, wxSizerFlags().Expand().Align( wxGROW ) );
	pInformationControlsSizer->Add( pFilterData, wxSizerFlags().Expand().Align( wxGROW ) );

//>>>>>>>>>>>>>>>
	m_pNotebook->AddPage(pInformationControlsPage, wxT("Statistics"), true );

	wxBoxSizer* pSizer = new wxBoxSizer(wxVERTICAL);
	pSizer->Add( m_pLowerSplitter, wxSizerFlags(1).Expand() );

	pPanel->SetSizer( pSizer );

// 	m_splitter2->SplitHorizontally( m_pLogWindow2, m_splitter, 0 );
// 	m_splitter->SplitHorizontally( m_pNotebook, m_pLogWindow, -150 );

	m_pUpperSplitter->SplitHorizontally( m_pFilterListCtrl, m_pNotebook, 200 );
	m_pLowerSplitter->SplitHorizontally( m_pUpperSplitter, m_pLogWindow, -130 );

	pInformationControlsPage->SetSizer( pInformationControlsSizer );

// 	SetClientSize( pInformationControlsSizer->GetMinSize() );
// 	pInformationControlsSizer->SetSizeHints( this );

	CreateStatusBar();
	SetStatusText( wxT( "MATRIX VISION 2009" ) );

	m_pIoctlMutex = new wxMutex();

	UpdateDlgControls();
	OpenFilter();
	DeviceList.clear();

	BuildDeviceList();
}

CaptureAnalyzerFrame::~CaptureAnalyzerFrame( void )
{
	SetupUpdateTimer( false );
	if( m_fd >= 0 )
		close( m_fd );
}

void CaptureAnalyzerFrame::OnAbout( wxCommandEvent& WXUNUSED( event ) )
{
	wxMessageBox( wxT( "Capture Analyzer Linux 2009 v0.1" ),
			wxT( "About Capture Analyzer" ), wxOK | wxICON_INFORMATION, this );
}

void CaptureAnalyzerFrame::OnQuit( wxCommandEvent& WXUNUSED( event ) )
{
	Close(TRUE);
}

void CaptureAnalyzerFrame::OnAdapterComboTextChanged( wxCommandEvent& event )
{
	if( DeviceList.empty() )
		return;

// 	DrvBindFilter();
}

void CaptureAnalyzerFrame::OnListDevices( wxCommandEvent& event )
{
	BuildDeviceList();
	return;
}

void CaptureAnalyzerFrame::OnToggleStatisticsUpdate( wxCommandEvent& e )
{
	bool boChecked = e.IsChecked();
	if( boChecked )
		DrvBindFilter();
	SetupUpdateTimer( boChecked );
	m_pMIAction_UpdateStatistics->Check( boChecked );
	m_pToolBar->ToggleTool( tbAction_UpdateStatistics, boChecked );
}

void CaptureAnalyzerFrame::OnTimer( wxTimerEvent& e )
{
	switch( e.GetId() )
	{
	case teListUpdate:
		DrvQueryStatistics();
		UpdateStatistics( &m_stats );
		break;
	default:
		break;
	}
}

void CaptureAnalyzerFrame::OnListDeleteAllItems( wxListEvent& )
{
	WriteLogMessage( wxString::Format( wxT("OnListDeleteAllItems\n")), m_ERROR_STYLE );
}

void CaptureAnalyzerFrame::OnListSelected( wxListEvent& e )
{
// 	WriteLogMessage( wxString::Format( wxT("OnListSelected\n")), m_ERROR_STYLE );
}

void CaptureAnalyzerFrame::OnListDeselected( wxListEvent& e )
{
// 	WriteLogMessage( wxString::Format( wxT("OnListDeselected\n")), m_ERROR_STYLE );
}

void CaptureAnalyzerFrame::OnBtnResetAdapterStatistics( wxCommandEvent& event )
{
	int ret = 0;

	m_pIoctlMutex->Lock();

	if( (ret = ioctl( m_fd, ANALYZER_RESET_IPv4_STATISTICS, &m_stats.IPv4Stat )) ) {
		WriteLogMessage( wxString::Format( wxT("Reset IPv4 statistics failed - ret=%d\n"), ret), m_ERROR_STYLE );
// 		printf("ANALYZER_RESET_IPv4_STATISTICS - ret=%d\n", ret);
	}

	m_pIoctlMutex->Unlock();
}

void CaptureAnalyzerFrame::OnBtnResetResendStatistics( wxCommandEvent& event )
{
	int ret = 0;

	m_pIoctlMutex->Lock();

	if( (ret = ioctl( m_fd, ANALYZER_RESET_RESEND_STATISTICS, &m_stats.ResendStat )) ) {
		WriteLogMessage( wxString::Format( wxT("Reset resend statistics failed - ret=%d\n"), ret), m_ERROR_STYLE );
// 		printf("ANALYZER_RESET_IPv4_STATISTICS - ret=%d\n", ret);
	}

	m_pIoctlMutex->Unlock();
}

void CaptureAnalyzerFrame::OnBtnResetFilterStatistics( wxCommandEvent& event )
{
	int ret = 0;

	m_pIoctlMutex->Lock();

	if( (ret = ioctl( m_fd, ANALYZER_RESET_FILTER_STATISTICS, &m_stats.FiltStat )) ) {
		WriteLogMessage( wxString::Format( wxT("Reset filter statistics failed - ret=%d\n"), ret), m_ERROR_STYLE );
// 		printf("ANALYZER_RESET_FILTER_STATISTICS - ret=%d\n", ret);
	}

	m_pIoctlMutex->Unlock();
}

void CaptureAnalyzerFrame::OpenFilter( void )
{
	string filename ("/dev/mvfd");

	if( (m_fd = open( filename.c_str(), O_RDWR )) < 0) {
		perror( filename.c_str() );
		WriteLogMessage( wxString::Format( wxT("Can't open /dev/mvfd\n")), m_ERROR_STYLE );
		WriteLogMessage( wxString::Format( wxT("Close this application, load mvnetfilter and try again!\n")), m_ERROR_STYLE );
// 		printf( "cannot open %s\n", filename.c_str() );
		return;
	}
}

void CaptureAnalyzerFrame::BuildDeviceList( void )
{
	int i = 0, size, ret = 0;
	uint32_t *ptmp = NULL;
	std::string ipv4str;
	wxString tmpwxstr, OldSelection;
// 	struct ioctl_object iop;

	if( !DeviceList.empty() ) {
		OldSelection = m_pAdapterCombo->GetValue();
// 		printf("Devicelist is not empty()\n");
// 		WriteLogMessage( wxString::Format( wxT("DeviceList is not empty\n")), m_MSG_STYLE );
		string tmpstr ( OldSelection.ToAscii() );
// 		WriteLogMessage( wxString::Format( wxT("OldSelection: %s\n"), OldSelection.c_str()), m_MSG_STYLE );
// 		cout << "OldSelection: " << tmpstr << endl;
	}

	m_pAdapterCombo->Clear();
	DeviceList.erase( DeviceList.begin(), DeviceList.end() );
	if( m_fd <= 0 )
		return;

	size = 10 * sizeof(uint32_t);
	m_pDeviceList =  (uint32_t*)malloc( size );
	memset(m_pDeviceList, 0x00, size);
	ptmp = m_pDeviceList;

	if( !m_pDeviceList )
		return;

	if( (ret = ioctl( m_fd, ANALYZER_LIST_DEVICES, m_pDeviceList )) ) {
		m_pAdapterCombo->Append( m_NoItemString );
		m_pAdapterCombo->Select(0);
		m_pToolBar->EnableTool( tbAction_UpdateStatistics, false );
// 		printf("ANALYZER_LIST_DEVICES failed - ret=%d\n", ret);
		WriteLogMessage( wxString::Format( wxT("No active Netfilter found\n")), m_ERROR_STYLE );
		return;
	}
	m_pToolBar->EnableTool( tbAction_UpdateStatistics, true );

	while( *ptmp != 0 ) {
// 		ipv4str = ConvertIntToIpv4String( *ptmp );
// 		wxString tmpstr( wxString::FromAscii( ipv4str.c_str() ) );
		wxString tmpstr = ConvertIntToIpv4wxString( *ptmp );
		m_pAdapterCombo->Append( tmpstr );
		DeviceList[tmpstr] = *ptmp;
		i++;
		ptmp++;
		WriteLogMessage( wxString::Format( wxT("Found device: %s\n"), tmpstr.c_str()), m_MSG_STYLE );
	}

	if( i == 0 ) {
		m_pAdapterCombo->Append( m_NoItemString );
	} else {
		if( (OldSelection.Len() > 0) && (OldSelection != m_NoItemString) ) {
			it_DevList = DeviceList.find(OldSelection);
			if( it_DevList != DeviceList.end() ) {
				m_pAdapterCombo->SetValue( OldSelection );
			} else 
				m_pAdapterCombo->Select(0);
		} else 
			m_pAdapterCombo->Select(0);
	}

	free(m_pDeviceList);
	m_pDeviceList = NULL;
}

void CaptureAnalyzerFrame::DrvBindFilter( void )
{
	int ret = 0;
	uint32_t Ipv4Adrr = 0;
	wxString ComboSelection;

	m_io.value = 0;
	ComboSelection = m_pAdapterCombo->GetValue();

	if( ComboSelection == m_NoItemString ) {
// 		cout << "Warning: No Filter active!" << endl;
		WriteLogMessage( wxString::Format( wxT("Warning: No Filter active\n")), m_ERROR_STYLE );
		return;
	}

// 	string tmpstr ( ComboSelection.ToAscii() );
// 	Ipv4Adrr = DeviceList.find(tmpstr)->second;
	Ipv4Adrr = DeviceList.find(ComboSelection)->second;

	m_io.value = Ipv4Adrr;

	if( (ret = ioctl( m_fd, ANALYZER_BIND_FILTER, &m_io )) ) {
// 		printf("ANALYZER_BIND_FILTER - ret=%d\n", ret);
		WriteLogMessage( wxString::Format( wxT("Bind Analyzer to device [%s] failed - ret=%d\n"), ComboSelection.c_str(), ret), m_ERROR_STYLE );
		return;
	}
	WriteLogMessage( wxString::Format( wxT("Bound with device: %s\n"), ComboSelection.c_str()), m_MSG_STYLE );

	m_pFilterListCtrl->InsertItem( 0, wxT("-")  );
	m_pFilterListCtrl->SetItemState( 0, wxLIST_STATE_SELECTED, wxLIST_MASK_STATE | wxLIST_MASK_TEXT );

	GetFilterInfo();
	m_pFilterListCtrl->SetItem( 0, lcFilterIPAddress, m_FilterIP );
	m_pFilterListCtrl->SetItem( 0, lcFilterPort, m_FilterPort );
	m_pFilterListCtrl->SetItem( 0, lcFilterPacketSize, m_PacketSize );
	m_pFilterListCtrl->SetItem( 0, lcGVCPClientPort, m_ClientPort );
	m_pFilterListCtrl->SetItem( 0, lcClientIP, m_ClientIP );

	return;
}

void CaptureAnalyzerFrame::SetupUpdateTimer( bool boActive )
{
	if( boActive && !m_ListUpdateTimer.IsRunning() )
	{
		m_pAdapterCombo->Enable(false);
		m_pBTNResetResendStatistics->Enable(true);
		m_pBTNResetFilterStatistics->Enable(true);
		DrvQueryStatistics();
		UpdateStatistics( &m_stats);
		m_ListUpdateTimer.SetOwner( this, teListUpdate );
		m_ListUpdateTimer.Start( TIMER_PERIOD );
	}
	else if( !boActive && m_ListUpdateTimer.IsRunning() )
	{
		m_ListUpdateTimer.Stop();
		m_pAdapterCombo->Enable(true);
		m_pBTNResetResendStatistics->Enable(false);
		m_pBTNResetFilterStatistics->Enable(false);
		BuildDeviceList();
		m_pFilterListCtrl->DeleteItem( 0 );
	}
}

void CaptureAnalyzerFrame::DrvQueryStatistics( void )
{
	int ret = 0;
	boGotAdapterStatistics = false;
	boGotResendStatistics = false;
	boGotFilterStatistics = false;

	if( DeviceList.empty() )
		return;

	m_pIoctlMutex->Lock();

	if( (ret = ioctl( m_fd, ANALYZER_GET_IPv4_STATISTICS, &m_stats.IPv4Stat )) ) {
// 		printf("ANALYZER_GET_IPv4_STATISTICS - ret=%d\n", ret);
		WriteLogMessage( wxString::Format( wxT("Query Ipv4 statistics failed- ret=%d\n"), ret), m_ERROR_STYLE );
		m_pIoctlMutex->Unlock();
		return;
	}
	boGotAdapterStatistics = true;

	if( (ret = ioctl( m_fd, ANALYZER_GET_RESEND_STATISTICS, &m_stats.ResendStat )) ) {
		WriteLogMessage( wxString::Format( wxT("Query resend statistics failed- ret=%d\n"), ret), m_ERROR_STYLE );
// 		printf("ANALYZER_GET_FILTER_STATISTICS - ret=%d\n", ret);
		m_pIoctlMutex->Unlock();
		return;
	}
	boGotResendStatistics = true;

	if( (ret = ioctl( m_fd, ANALYZER_GET_FILTER_STATISTICS, &m_stats.FiltStat )) ) {
		WriteLogMessage( wxString::Format( wxT("Query filter statistics failed- ret=%d\n"), ret), m_ERROR_STYLE );
// 		printf("ANALYZER_GET_FILTER_STATISTICS - ret=%d\n", ret);
		m_pIoctlMutex->Unlock();
		return;
	}
	boGotFilterStatistics = true;

	m_pIoctlMutex->Unlock();
}

void CaptureAnalyzerFrame::UpdateStatistics( struct _Statistics* stats )
{
	m_pSTPacketsThroughPTReceivePacket->SetLabel( boGotAdapterStatistics ? wxString::Format( wxT("%llu"), stats->IPv4Stat.PTRcvPktCt ) : wxT("-") );
	m_pSTPacketsDroppedInPtReceivePacket->SetLabel( boGotAdapterStatistics ? wxString::Format( wxT("%llu"), stats->IPv4Stat.PTRcvPktDropped ) : wxT("-") );
	m_pSTPacketBytesCopiedCount->SetLabel( boGotAdapterStatistics ? wxString::Format( wxT("%llu"), (stats->IPv4Stat.PktBytesCopied >> 10) ) : wxT("-") );

	m_pSTResendCmdsIssued->SetLabel( boGotResendStatistics ? wxString::Format( wxT("%llu"), stats->ResendStat.ResendCmdsIssued ) : wxT("-") );
	m_pSTReRequestedPackets->SetLabel( boGotResendStatistics ? wxString::Format( wxT("%llu"), stats->ResendStat.ReRequestedPacketCnt ) : wxT("-") );
	m_pSTRecoveredPackets->SetLabel( boGotResendStatistics ? wxString::Format( wxT("%llu"), stats->ResendStat.RecoveredPacketCnt ) : wxT("-") );

	m_pSTAnnouncedBuffers->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.AnnouncedBufferCnt ) : wxT("-") );
	m_pSTBuffersInQueue->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%lld"), stats->FiltStat.BufferStatistics.BuffersInQueue ) : wxT("-") );
	m_pSTBuffersQueued->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.QueuedBufferCnt ) : wxT("-") );
	m_pSTBuffersCanceled->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.CanceledBufferCnt ) : wxT("-") );
	m_pSTBuffersTimedOut->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.TimedOutBufferCnt ) : wxT("-") );
	m_pSTBuffersSuccessfullyReturned->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.SuccessfulBufferCnt ) : wxT("-") );
	m_pSTBuffersWithUnknownError->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.UnknownErrorBufferCnt ) : wxT("-") );
	m_pSTInvalidIO->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.BufferStatistics.InvalidIOBuffer ) : wxT("-") );


	m_pSTProcessedLeaders->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.ProcessedPackets.Leaders ) : wxT("-") );
	m_pSTProcessedTrailers->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.ProcessedPackets.Trailers ) : wxT("-") );
	m_pSTProcessedPayload->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.ProcessedPackets.Payload ) : wxT("-") );
	m_pSTDuplicatePacket->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.ProcessedPackets.Duplicate ) : wxT("-") );
	m_pSTProcessedUnknown->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.ProcessedPackets.Unknown ) : wxT("-") );

	m_pSTDroppedLeaders->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.DroppedPackets.Leaders ) : wxT("-") );
	m_pSTDroppedTrailers->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.DroppedPackets.Trailers ) : wxT("-") );
	m_pSTDroppedPayload->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.DroppedPackets.Payload ) : wxT("-") );
	m_pSTDroppedUnknown->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.DroppedPackets.Unknown ) : wxT("-") );

	m_pSTMissingLeaders->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.MissingLeaders ) : wxT("-") );
	m_pSTMissingTrailers->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.MissingTrailers ) : wxT("-") );
	m_pSTMissingPayloadPackets->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.MissingPayloadPackets ) : wxT("-") );


	m_pSTCompleteFrameCnt->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.CompleteFrames ) : wxT("-") );
	m_pSTIncompleteFrameCnt->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.IncompleteFrames ) : wxT("-") );
	m_pSTFaultyImages->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.FaultyImages ) : wxT("-") );

	m_pSTReconstructedFrames->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.ReconstructedFrames ) : wxT("-") );
	m_pSTUnsuccessfullyReconstructedFrames->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.UnsuccessfullyReconstructedFrames ) : wxT("-") );

	m_pSTLostFrames->SetLabel( boGotFilterStatistics ? wxString::Format( wxT("%llu"), stats->FiltStat.FrameStatistics.LostFrames ) : wxT("-") );

}

void CaptureAnalyzerFrame::UpdateDlgControls( void )
{
	m_pBTNResetResendStatistics->Enable(false);
	m_pBTNResetFilterStatistics->Enable(false);

	m_pSTPacketsThroughPTReceivePacket->Enable( true );
	m_pSTPacketsDroppedInPtReceivePacket->Enable( true );
	m_pSTPacketBytesCopiedCount->Enable( true );

	m_pSTAnnouncedBuffers->Enable( true );
	m_pSTBuffersInQueue->Enable( true );
	m_pSTBuffersQueued->Enable( true );
	m_pSTBuffersCanceled->Enable( true );
	m_pSTBuffersTimedOut->Enable( true );
	m_pSTBuffersSuccessfullyReturned->Enable( true );
	m_pSTBuffersWithUnknownError->Enable( true );
	m_pSTInvalidIO->Enable( true );
	m_pSTMissingLeaders->Enable( true );
	m_pSTMissingTrailers->Enable( true );
	m_pSTMissingPayloadPackets->Enable( true );
	m_pSTCompleteFrameCnt->Enable( true );
	m_pSTIncompleteFrameCnt->Enable( true );
	m_pSTFaultyImages->Enable( true );
	m_pSTReconstructedFrames->Enable( true );
	m_pSTUnsuccessfullyReconstructedFrames->Enable( true );
	m_pSTLostFrames->Enable( true );
	m_pSTDroppedLeaders->Enable( true );
	m_pSTDroppedTrailers->Enable( true );
	m_pSTDroppedPayload->Enable( true );
	m_pSTDroppedUnknown->Enable( true );
	m_pSTProcessedLeaders->Enable( true );
	m_pSTProcessedTrailers->Enable( true );
	m_pSTProcessedPayload->Enable( true );
	m_pSTProcessedUnknown->Enable( true );
}

void CaptureAnalyzerFrame::WriteLogMessage( const wxString& msg, const wxTextAttr& style /* = wxTextAttr(wxColour(0, 0, 0)) */ )
{
	if( m_pLogWindow )
	{
		long posBefore = m_pLogWindow->GetLastPosition();
		m_pLogWindow->WriteText( msg );
		long posAfter = m_pLogWindow->GetLastPosition();
		m_pLogWindow->SetStyle( posBefore, posAfter, style );
	}
}

void CaptureAnalyzerFrame::GetFilterInfo( void )
{
	int ret;
	FilterAnalyzerInfo FiltInfo;

	if( !(ret = ioctl( m_fd, ANALYZER_GET_FILTER_INFO, &FiltInfo )) ) {
		m_FilterIP = ConvertIntToIpv4wxString( FiltInfo.FilterIP );
		m_FilterPort = wxString::Format( wxT( "%d" ), FiltInfo.FilterPort );
		m_PacketSize = wxString::Format( wxT( "%d" ), FiltInfo.PacketSize );
		m_ClientIP = ConvertIntToIpv4wxString( FiltInfo.ClientIP );
		m_ClientPort = wxString::Format( wxT( "%d" ), FiltInfo.ClientPort );
	} else {
		m_FilterIP = wxString::Format( wxT( "0.0.0.0" ), FiltInfo.FilterIP );
		m_FilterPort = wxString::Format( wxT( "x-x-x" ), FiltInfo.FilterPort );
		m_PacketSize = wxString::Format( wxT( "x-x-x" ), FiltInfo.PacketSize );
		m_ClientIP = wxString::Format( wxT( "0.0.0.0" ), FiltInfo.ClientIP );
		m_ClientPort = wxString::Format( wxT( "x-x-x" ), FiltInfo.ClientPort );
		WriteLogMessage( wxT("Query filter port failed\n"), m_ERROR_STYLE );
	}

	return;
}


// ----------------------------------------------------------------------------
// CaptureSplitterWindow
// ----------------------------------------------------------------------------
BEGIN_EVENT_TABLE(CaptureSplitterWindow, wxSplitterWindow)
//     EVT_SPLITTER_SASH_POS_CHANGED(wxID_ANY, CaptureSplitterWindow::OnPositionChanged)
//     EVT_SPLITTER_SASH_POS_CHANGING(wxID_ANY, CaptureSplitterWindow::OnPositionChanging)
// 
//     EVT_SPLITTER_DCLICK(wxID_ANY, MySplitterWindow::OnDClick)
// 
//     EVT_SPLITTER_UNSPLIT(wxID_ANY, MySplitterWindow::OnUnsplitEvent)
END_EVENT_TABLE()

CaptureSplitterWindow::CaptureSplitterWindow(wxFrame *parent)
                : wxSplitterWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSP_3D | wxSP_LIVE_UPDATE | wxCLIP_CHILDREN /* | wxSP_NO_XP_THEME */ )
{
    m_frame = parent;
}

