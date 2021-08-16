package smb

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSessionSetup2Res(t *testing.T) {
	//negRes := SessionSetup2Res{}
	buf, _ := hex.DecodeString("fe534d4240000100160000c001000100010000000000000002000000000000000000000000000000090000000078000000000000000000000000000000000000090000004800bd00a181ba3081b7a0030a0101a10c060a2b06010401823702020aa281a104819e4e544c4d53535000020000000e000e003800000005828aa27061ee132005d5a4000000000000000058005800460000000a00614a0000000f5a0044004a002d0030003500310002000e005a0044004a002d0030003500310001000e005a0044004a002d0030003500310004000e007a0064006a002d0030003500310003000e007a0064006a002d00300035003100070008002d108a2e658ad70100000000")
	negRes := NewSessionSetup2ResV2(buf)
	fmt.Println(negRes.SecurityBlob)
	//fmt.Printf("%x\n", negRes.SecurityBlob)
	fmt.Println(int(negRes.SecurityBufferLength))
	fmt.Println(int(negRes.SecurityBufferOffset))
	fmt.Printf("%x\n", buf[int(negRes.SecurityBufferOffset):int(negRes.SecurityBufferOffset)+int(negRes.SecurityBufferLength)])
	//l1 := strconv.FormatInt(int64(negRes.SecurityBufferLength), 16)
	//fmt.Println(l1)
	//o := strconv.FormatInt(int64(negRes.SecurityBufferLength), 16)
	//fmt.Println(o)
}
