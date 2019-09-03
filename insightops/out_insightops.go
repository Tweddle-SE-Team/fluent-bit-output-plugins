package main

import (
	"C"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/fluent/fluent-bit-go/output"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"unsafe"
)

type InsightOPSContext struct {
	Tokens      map[string]string
	TagPosition int
	TagRegex    *regexp.Regexp
	Protocol    string
	Address     string
}

var (
	contexts []*InsightOPSContext
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Gets called only once when the plugin.so is loaded
	return output.FLBPluginRegister(def, "insightops", "InsightOPS fluent-bit output plugin")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	region := output.FLBPluginConfigKey(plugin, "region")
	protocol := output.FLBPluginConfigKey(plugin, "protocol")
	tag_regex := output.FLBPluginConfigKey(plugin, "tag_regex")
	tag_key := output.FLBPluginConfigKey(plugin, "tag_key")
	path := output.FLBPluginConfigKey(plugin, "path")
	if region == "" {
		log.Println("[error] [out_insightops] Region is required")
		return output.FLB_ERROR
	}
	if path == "" && os.Getenv("INSIGHTOPS_TOKENS_JSON") == "" {
		log.Println("[error] [out_insightops] Tokens config path is required")
		return output.FLB_ERROR
	}
	regex, tag_position, err := wordPositionAtRegex(tag_regex, tag_key)
	if err != nil {
		log.Printf("[error] [out_insightops] %v\n")
		return output.FLB_ERROR
	}
	var tokens map[string]string
	var json_config_data []byte
	if path != "" {
		json_file, err := os.Open(path)
		if err != nil {
			log.Printf("[error] [out_insightops] %v\n", err)
		}
		defer json_file.Close()
		json_config_data, _ = ioutil.ReadAll(json_file)
	} else {
		json_config_data = []byte(os.Getenv("INSIGHTOPS_TOKENS_JSON"))
	}
	if err := json.Unmarshal(json_config_data, &tokens); err != nil {
		log.Println("[error] [out_insightops] Cannot parse tokens config")
		return output.FLB_ERROR
	}
	if protocol == "" {
		protocol = "tcp"
	}
	address := fmt.Sprintf("%s.data.logs.insight.rapid7.com:443", region)
	if err != nil {
		log.Println("[error] [out_insightops] ", err)
		return output.FLB_ERROR
	}
	contextId := len(contexts)
	contexts = append(contexts, &InsightOPSContext{
		Tokens:      tokens,
		TagPosition: tag_position,
		TagRegex:    regex,
		Address:     address,
		Protocol:    protocol,
	})
	output.FLBPluginSetContext(plugin, contextId)
	log.Printf("[ info] [out_insightops] Initializing plugin for region %s\n", region)
	return output.FLB_OK
}

func connectInsight(protocol, address string) (*tls.Conn, error) {
	conf := &tls.Config{}
	return tls.Dial(protocol, address, conf)
}

func wordPositionAtRegex(regex string, word string) (*regexp.Regexp, int, error) {
	if regex != "" && word != "" {
		tag_regex := regexp.MustCompile(regex)
		tokens := tag_regex.SubexpNames()
		for index, token := range tokens {
			if word == token {
				return tag_regex, index, nil
			}
		}
		return nil, -1, fmt.Errorf("Invalid Tag_Key or Tag_Regex parameters. Tag_Regex should contain Tag_Key")
	}
	return nil, -1, nil
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	var (
		ret    int
		record map[interface{}]interface{}
		buffer bytes.Buffer
	)
	contextId := output.FLBPluginGetContext(ctx).(int)
	context := contexts[contextId]
	connection, err := connectInsight(context.Protocol, context.Address)
	if err != nil {
		log.Println("[error] [out_insightops] ", err)
		return output.FLB_ERROR
	}
	defer connection.Close()
	dec := output.NewDecoder(data, int(length))
	fluent_tag := C.GoString(tag)
	fmt.Printf("[ info] [out_insightops] processing records for tag %s\n", fluent_tag)
	if context.TagRegex != nil {
		match := context.TagRegex.FindStringSubmatch(fluent_tag)
		if match != nil {
			fluent_tag = match[context.TagPosition]
			fmt.Printf("[ info] [out_insightops] records for tag %s\n", fluent_tag)
		}
	}
	token := context.Tokens[fluent_tag]
	if token == "" {
		fmt.Printf("[ info] [out_insightops] No logs found for %s tag\n", fluent_tag)
		return output.FLB_OK
	}
	for {
		buffer.Reset()
		ret, _, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}
		o := make(map[string]interface{})
		for k, v := range record {
			switch t := v.(type) {
			case []byte:
				o[k.(string)] = string(t)
			default:
				o[k.(string)] = v
			}
		}
		data, err := json.Marshal(o)
		if err != nil {
			log.Println("[error] [out_insightops] Couldn't convert record to JSON: ", err)
		}
		buffer.WriteString(token)
		buffer.WriteString(" ")
		buffer.Write(data)
		buffer.WriteString("\r\n")
		_, err = connection.Write(buffer.Bytes())
		if err != nil {
			log.Printf("[ warn] [out_insightops] Wasn't able to write: %v\n", err)
			return output.FLB_RETRY
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
