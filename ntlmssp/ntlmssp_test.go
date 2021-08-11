package ntlmssp

import (
	"strings"
	"testing"

	"go-smb/smb/encoder"
)

/*
  Malformed NTLMSSP challenge, in that the first AvPair has an invalid
  type code, and has an absurd (0x910e) length for the field.
*/
const problematicResponse = "" +
	"\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x08\x00\x08\x00" +
	"\x38\x00\x00\x00\x05\x02\x8a\xa2\x73\xcb\xa1\xb4\x21\x03\xf7\xfb" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x40\x00\x40\x00\x00\x00" +
	"\x0a\x00\x61\x4a\x00\x00\x00\x0f\x41\x00\x53\x00\x55\x00\x53\x00" +
	"\x17\xe9\x0e\x91\x31\xe7\xb2\xce\xac\x29\x59\xba\x01\x00\x08\x00" +
	"\x41\x00\x53\x00\x55\x00\x53\x00\x04\x00\x08\x00\x41\x00\x53\x00" +
	"\x55\x00\x53\x00\x03\x00\x08\x00\x41\x00\x53\x00\x55\x00\x53\x00" +
	"\x07\x00\x08\x00\x24\x35\x53\x3a\x25\xff\xd6\x01\x00\x00\x00\x00"

func TestMalformedChallenge(t *testing.T) {
	challenge := NewChallenge()
	if err := encoder.Unmarshal([]byte(problematicResponse), &challenge); err != nil {
		if !strings.HasPrefix(err.Error(), "field 'Value'") {
			t.Errorf("Expected error on field Value but failed elsewhere: %v", err)
		}
	}
}
