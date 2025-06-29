package discover

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type UDPPacketPayload struct {
	PrimaryIP    string   `json:"primaryIP,omitempty"`
	SecondaryIPs []string `json:"secondaryIPs,omitempty"`
}

func EncodeUDPPacket(primaryIP string, secondaryIPs []string) ([]byte, error) {
	payload := UDPPacketPayload{
		PrimaryIP:    primaryIP,
		SecondaryIPs: secondaryIPs,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return append(append(UDPPayloadPrefix, data...), UDPPayloadSuffix...), nil
}

func DecodeUDPPacket(data []byte) (*UDPPacketPayload, error) {
	if len(data) < len(UDPPayloadPrefix)+len(UDPPayloadSuffix) {
		return nil, fmt.Errorf("not enough data") // Not enough data to decode
	}

	start := bytes.Index(data, UDPPayloadPrefix)
	if start < 0 {
		return nil, fmt.Errorf("missing UDP payload prefix")
	}
	start += len(UDPPayloadPrefix)
	end := bytes.Index(data, UDPPayloadSuffix)
	if end < 0 || end <= start {
		return nil, fmt.Errorf("missing or invalid UDP payload suffix")
	}

	var payload UDPPacketPayload
	err := json.Unmarshal(data[start:end], &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal UDP payload: %w", err)
	}
	return &payload, nil
}
