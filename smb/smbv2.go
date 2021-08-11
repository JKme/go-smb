package smb

import (
	"go-smb/gss"
)

type HeaderV2 struct {
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

type SessionSetup2Res struct {
	HeaderV2
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

func bytes2Uint(bs []byte, endian byte) uint64 {
	var u uint64
	if endian == '>' {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[i]) << (8 * (len(bs) - i - 1))
		}
	} else {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[len(bs)-i-1]) << (8 * (len(bs) - i - 1))
		}
	}
	return u
}

const ProtocolSmb2 = "\xFESMB"

//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
func newHeader() HeaderV2 {
	return HeaderV2{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  0,
		Status:        0,
		Command:       0,
		Credits:       0,
		Flags:         0,
		NextCommand:   0,
		MessageID:     0,
		Reserved:      0,
		TreeID:        0,
		SessionID:     0,
		Signature:     make([]byte, 16),
	}
}

func NewSessionSetup2Res(bs []byte) *SessionSetup2Res {
	tokenBlob, _ := gss.NewNegTokenResp()
	resp := SessionSetup2Res{}
	if bs == nil {
		resp = SessionSetup2Res{
			HeaderV2:     newHeader(),
			SecurityBlob: &tokenBlob,
		}
	} else {
		resp.UnMarshal(bs)
	}
	return &resp
}

func (resp *SessionSetup2Res) UnMarshal(bs []byte) {
	copy(resp.ProtocolID, bs[:8])
	//resp.StructureSize = uint32(bytes2Uint(bs[8:12], '<'))
}
