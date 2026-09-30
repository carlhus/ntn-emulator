package ngap

import (
	"fmt"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
)

// NGSetupHandler handles NG Setup procedure with AMF
type NGSetupHandler struct {
	client  *NGAPClient
	gnbID   []byte
	gnbName string
	tac     int
}

// NewNGSetupHandler creates a new NG Setup handler
func NewNGSetupHandler(client *NGAPClient, gnbID []byte, gnbName string, tac int) *NGSetupHandler {
	return &NGSetupHandler{
		client:  client,
		gnbID:   gnbID,
		gnbName: gnbName,
		tac:     tac,
	}
}

// PerformNGSetup performs the NG Setup procedure
func (h *NGSetupHandler) PerformNGSetup() error {
	// Build NG Setup Request
	ngSetupRequest, err := h.buildNGSetupRequest()
	if err != nil {
		return fmt.Errorf("failed to build NG Setup Request: %w", err)
	}

	// Send NG Setup Request
	_, err = h.client.Send(ngSetupRequest)
	if err != nil {
		return fmt.Errorf("failed to send NG Setup Request: %w", err)
	}

	// Receive NG Setup Response
	recvBuf := make([]byte, 2048)
	n, err := h.client.Receive(recvBuf)
	if err != nil {
		return fmt.Errorf("failed to receive NG Setup Response: %w", err)
	}

	// Decode NG Setup Response
	ngapPdu, err := message.Parse(recvBuf[:n])
	if err != nil {
		return fmt.Errorf("failed to decode NG Setup Response: %w", err)
	}

	// Verify it's a successful response
	if _, ok := ngapPdu.(*message.NGSetupResponse); !ok {
		return fmt.Errorf("NG Setup failed: unexpected NGAP message %T", ngapPdu)
	}

	return nil
}

// buildNGSetupRequest builds an NG Setup Request NGAP message
func (h *NGSetupHandler) buildNGSetupRequest() ([]byte, error) {
	ngSetupRequest := &message.NGSetupRequest{
		// Global RAN Node ID
		GlobalRANNodeID: h.buildGlobalRANNodeID(),
		// Supported TA List
		SupportedTAList: h.buildSupportedTAList(),
		// Default Paging DRX
		DefaultPagingDRX: &ie.PagingDRX{
			Value: ie.PagingDRXPresentV128,
		},
	}

	// Add RAN Node Name (optional, but useful for NTN identification)
	if h.gnbName != "" {
		ngSetupRequest.RANNodeName = &ie.RANNodeName{
			Value: aper.PrintableString(h.gnbName),
		}
	}

	// Encode the PDU
	return ngSetupRequest.MarshalBinary()
}

// buildGlobalRANNodeID builds the Global RAN Node ID
func (h *NGSetupHandler) buildGlobalRANNodeID() *ie.GlobalRANNodeID {
	return &ie.GlobalRANNodeID{
		Choice: &ie.GlobalGNBID{
			PLMNIdentity: &ie.PLMNIdentity{
				Value: aper.OctetString("\x02\xf8\x39"), // MCC=208, MNC=93 (correct encoding)
			},
			GNBID: &ie.GNBID{
				Choice: &ie.GNBIDForGNBID{
					Value: aper.BitString{
						Bytes:     h.gnbID,
						BitLength: uint64(len(h.gnbID) * 8),
					},
				},
			},
		},
	}
}

// buildSupportedTAList builds the Supported TA List
func (h *NGSetupHandler) buildSupportedTAList() *ie.SupportedTAList {
	broadcastPLMN := ie.BroadcastPLMNItem{
		PLMNIdentity: &ie.PLMNIdentity{
			Value: aper.OctetString("\x02\xf8\x39"), // MCC=208, MNC=93 (correct encoding)
		},
		TAISliceSupportList: &ie.SliceSupportList{
			List: []ie.SliceSupportItem{
				{
					SNSSAI: &ie.SNSSAI{
						SST: &ie.SST{
							Value: aper.OctetString("\x01"),
						},
						SD: &ie.SD{
							Value: aper.OctetString("\x01\x02\x03"),
						},
					},
				},
			},
		},
	}

	return &ie.SupportedTAList{
		List: []ie.SupportedTAItem{
			{
				TAC: &ie.TAC{
					Value: aper.OctetString{uint8(h.tac >> 16), uint8(h.tac >> 8), uint8(h.tac)},
				},
				BroadcastPLMNList: &ie.BroadcastPLMNList{
					List: []ie.BroadcastPLMNItem{broadcastPLMN},
				},
			},
		},
	}
}
