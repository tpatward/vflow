//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    marshal.go
//: details: encoding of each decoded netflow v9 data sets into protobuf format
//: author:  Tapan Patwardhan
//: date:    06/8/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

package netflow9

import (
	"bytes"
	"errors"
	"strconv"
)

var errUknownProtobufMarshalDataType = errors.New("unknown data type to protobuf")

// ProtoBufMarshal encodes netflow v9 message into Protobuf format
func (m *Message) ProtoBufMarshal(b *bytes.Buffer) ([]byte, error) {
	
	// encode agent id
	m.protoBufAgent(b)

	// encode header
	m.protoBufHeader(b)

	// encode data sets
	if err := m.protoBufDataSet(b); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (m *Message) protoBufDataSet(b *bytes.Buffer) error {
	var (
		length   int
		dsLength int
		err      error
	)

	dsLength = len(m.DataSets)

	for i := range m.DataSets {
		length = len(m.DataSets[i])

		for j := range m.DataSets[i] {
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].ID), 10))
			err = m.writeValue(b, i, j)
		}
	}

	b.WriteByte(']')

	return err
}

func (m *Message) protoBufDataSetFlat(b *bytes.Buffer) error {
	var (
		length   int
		dsLength int
		err      error
	)

	dsLength = len(m.DataSets)

	for i := range m.DataSets {
		length = len(m.DataSets[i])

		for j := range m.DataSets[i] {
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].ID), 10))
			err = m.writeValue(b, i, j)
		}

	}

	return err
}

func (m *Message) protoBufHeader(b *bytes.Buffer) {
	b.WriteString(strconv.FormatInt(int64(m.Header.Version), 10))
	b.WriteString(strconv.FormatInt(int64(m.Header.Count), 10))
	b.WriteString(strconv.FormatInt(int64(m.Header.SysUpTime), 10))
	b.WriteString(strconv.FormatInt(int64(m.Header.UNIXSecs), 10))
	b.WriteString(strconv.FormatInt(int64(m.Header.SeqNum), 10))
	b.WriteString(strconv.FormatInt(int64(m.Header.SrcID), 10))
}

func (m *Message) protoBufAgent(b *bytes.Buffer) {
	//b.WriteString("\"AgentID\":\"")
	b.WriteString(m.AgentID)
	//b.WriteString("\",")
}

func (m *Message) writeValue(b *bytes.Buffer, i, j int) error {
	/*
		switch m.DataSets[i][j].Value.(type) {
		case uint:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(uint)), 10))
		case uint8:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(uint8)), 10))
		case uint16:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(uint16)), 10))
		case uint32:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(uint32)), 10))
		case uint64:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(uint64)), 10))
		case int:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(int)), 10))
		case int8:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(int8)), 10))
		case int16:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(int16)), 10))
		case int32:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(int32)), 10))
		case int64:
			b.WriteString(strconv.FormatInt(int64(m.DataSets[i][j].Value.(int64)), 10))
		case float32:
			b.WriteString(strconv.FormatFloat(float64(m.DataSets[i][j].Value.(float32)), 'E', -1, 32))
		case float64:
			b.WriteString(strconv.FormatFloat(m.DataSets[i][j].Value.(float64), 'E', -1, 64))
		case string:
			b.WriteByte('"')
			b.WriteString(m.DataSets[i][j].Value.(string))
			b.WriteByte('"')
		case net.IP:
			b.WriteByte('"')
			b.WriteString(m.DataSets[i][j].Value.(net.IP).String())
			b.WriteByte('"')
		case net.HardwareAddr:
			b.WriteByte('"')
			b.WriteString(m.DataSets[i][j].Value.(net.HardwareAddr).String())
			b.WriteByte('"')
		case []uint8:
			b.WriteByte('"')
			b.WriteString("0x" + hex.EncodeToString(m.DataSets[i][j].Value.([]uint8)))
			b.WriteByte('"')
		default:
			return errUknownMarshalDataType
		}
	*/
	return nil
}
