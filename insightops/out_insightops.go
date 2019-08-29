package main

import (
	"C"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/fluent/fluent-bit-go/output"
	"log"
	"runtime"
	"strconv"
	"unsafe"
)

type InsightOPSContext struct {
	Connection *tls.Conn
	Token      string
	Retries    int
}

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Gets called only once when the plugin.so is loaded
	return output.FLBPluginRegister(def, "insightops", "InsightOPS fluent-bit output plugin")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	region := output.FLBPluginConfigKey(plugin, "region")
	port := output.FLBPluginConfigKey(plugin, "port")
	protocol := output.FLBPluginConfigKey(plugin, "protocol")
	max_retries := output.FLBPluginConfigKey(plugin, "max_retries")
	token := output.FLBPluginConfigKey(plugin, "token")
	if region == "" {
		log.Println("[out_syslog] ERROR: Region is required")
		return output.FLB_ERROR
	}
	if token == "" {
		log.Println("[out_syslog] ERROR: Token is required")
		return output.FLB_ERROR
	}
	if port == "" {
		port = "10000"
	}
	if protocol == "" {
		protocol = "tcp"
	}
	if max_retries == "" {
		max_retries = "3"
	}
	conf := &tls.Config{}
	address := fmt.Sprintf("%s.data.logs.insight.rapid7.com", region)
	conn, err := tls.Dial(protocol, address, conf)
	if err != nil {
		log.Println(err)
		return output.FLB_ERROR
	}
	defer conn.Close()
	retries, err := strconv.Atoi(max_retries)
	if err != nil {
		log.Println(err)
		return output.FLB_ERROR
	}
	context := &InsightOPSContext{
		Connection: conn,
		Token:      token,
		Retries:    retries,
	}
	output.FLBPluginSetContext(plugin, unsafe.Pointer(context))
	runtime.KeepAlive(conn)
	log.Printf("[out_insightops] Initializing plugin for region %s", region)
	return output.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	var (
		ret    int
		record map[interface{}]interface{}
	)
	context := (*InsightOPSContext)(ctx)
	dec := output.NewDecoder(data, int(length))
	for {
		ret, _, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}
		data, err := json.Marshal(record)
		if err != nil {
			log.Println("Couldn't convert record to JSON: ", err)
		}
		for retry := 1; retry <= (*context).Retries; retry++ {
			_, err := (*context).Connection.Write(data)
			if err != nil {
				log.Printf("Attempt %d: %v", retry, err)
				continue
			}
			break
		}
	}
	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	return output.FLB_OK
}

func main() {
}