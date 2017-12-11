package dnsutils

/*
#cgo CFLAGS : -I../../include
#cgo LDFLAGS: -L../../lib -lm -lcurl -lcrypto -lurl_cloud64

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include "urllibhandler.h"
*/
import "C"

import (
	"fmt"
	"reflect"
	"unsafe"
)

// Record is the tencent urlsafe detected result
type Record struct {
	Url       string
	UrlType   int
	EvilClass int
	EvilType  int
	Level     int
}

// Struct2Map convert a struct to map
func (obj Record) Struct2Map() map[string]interface{} {
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)

	var data = make(map[string]interface{})
	for i := 0; i < t.NumField(); i++ {
		data[t.Field(i).Name] = v.Field(i).Interface()
	}
	return data
}

// UrlLibDetect is a function to check is the inputUrl a evil url
func UrlLibDetect(url string) (*Record, error) {
	rv := new(Record)
	cUrl := C.CString(url)
	defer C.free(unsafe.Pointer(cUrl))
	uiUrlType := C.uint(0)
	uiEvilType := C.uint(0)
	uiLevel := C.uint(0)
	uiEvilClass := C.uint(0)
	szParameter := C.CString("")
	defer C.free(unsafe.Pointer(szParameter))

	if iRet := C.UrlLibDetect(cUrl, &uiUrlType, &uiEvilType, &uiLevel, szParameter); iRet != 0x00 && iRet != 0x52 {
		err := fmt.Errorf("url:%s\tUrlLibDetect url failed! iRet:%#x", url, iRet)
		return rv, err
	}
	if iRetConv := C.convType2Class(uiEvilType, &uiEvilClass); iRetConv != 0x00 {
		err := fmt.Errorf("url:%s\tconvType2Class url failed! iRet:%#x", url, iRetConv)
		return rv, err
	}
	rv.Url = url
	rv.UrlType = int(uiUrlType)
	rv.EvilClass = int(uiEvilClass)
	rv.EvilType = int(uiEvilType)
	rv.Level = int(uiLevel)
	return rv, nil
}

// UrlLibInit is a function to initialize the lib and check is the licence.conf legal
func UrlLibInit(urlLibShmKey int, urlLibMaxCnt int, confPath string) error {
	pConf := C.CString(confPath)
	defer C.free(unsafe.Pointer(pConf))
	cUrllibShmKey := C.uint32_t(urlLibShmKey)
	cUrllibMaxCnt := C.uint32_t(urlLibMaxCnt)

	iErrCode := C.int(0)
	if !(C.UrlLibInit(cUrllibShmKey, cUrllibMaxCnt, pConf, &iErrCode)) {
		return fmt.Errorf("UrlLibInit Failed\tErrcode:%#x", iErrCode)
	}
	return nil
}
