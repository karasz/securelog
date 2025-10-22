package securelog

import (
	"fmt"

	pb "github.com/karasz/securelog/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToProtoInitCommitment converts InitCommitment to protobuf message
func ToProtoInitCommitment(c InitCommitment) *pb.InitCommitment {
	return &pb.InitCommitment{
		LogId:      c.LogID,
		StartTime:  timestamppb.New(c.StartTime),
		KeyA0:      c.KeyA0[:],
		KeyB0:      c.KeyB0[:],
		UpdateFreq: c.UpdateFreq,
	}
}

// FromProtoInitCommitment converts protobuf message to InitCommitment
func FromProtoInitCommitment(p *pb.InitCommitment) (InitCommitment, error) {
	var c InitCommitment
	c.LogID = p.LogId
	c.StartTime = p.StartTime.AsTime()

	if len(p.KeyA0) != KeySize {
		return c, fmt.Errorf("invalid KeyA0 size: expected %d, got %d", KeySize, len(p.KeyA0))
	}
	copy(c.KeyA0[:], p.KeyA0)

	if len(p.KeyB0) != KeySize {
		return c, fmt.Errorf("invalid KeyB0 size: expected %d, got %d", KeySize, len(p.KeyB0))
	}
	copy(c.KeyB0[:], p.KeyB0)

	c.UpdateFreq = p.UpdateFreq
	return c, nil
}

// ToProtoOpenMessage converts OpenMessage to protobuf message
func ToProtoOpenMessage(o OpenMessage) *pb.OpenMessage {
	return &pb.OpenMessage{
		LogId:      o.LogID,
		OpenTime:   timestamppb.New(o.OpenTime),
		FirstIndex: o.FirstIndex,
		FirstTagV:  o.FirstTagV[:],
		FirstTagT:  o.FirstTagT[:],
	}
}

// FromProtoOpenMessage converts protobuf message to OpenMessage
func FromProtoOpenMessage(p *pb.OpenMessage) (OpenMessage, error) {
	var o OpenMessage
	o.LogID = p.LogId
	o.OpenTime = p.OpenTime.AsTime()
	o.FirstIndex = p.FirstIndex

	if len(p.FirstTagV) != 32 {
		return o, fmt.Errorf("invalid FirstTagV size: expected 32, got %d", len(p.FirstTagV))
	}
	copy(o.FirstTagV[:], p.FirstTagV)

	if len(p.FirstTagT) != 32 {
		return o, fmt.Errorf("invalid FirstTagT size: expected 32, got %d", len(p.FirstTagT))
	}
	copy(o.FirstTagT[:], p.FirstTagT)

	return o, nil
}

// ToProtoCloseMessage converts CloseMessage to protobuf message
func ToProtoCloseMessage(c CloseMessage) *pb.CloseMessage {
	return &pb.CloseMessage{
		LogId:      c.LogID,
		CloseTime:  timestamppb.New(c.CloseTime),
		FinalIndex: c.FinalIndex,
		FinalTagV:  c.FinalTagV[:],
		FinalTagT:  c.FinalTagT[:],
	}
}

// FromProtoCloseMessage converts protobuf message to CloseMessage
func FromProtoCloseMessage(p *pb.CloseMessage) (CloseMessage, error) {
	var c CloseMessage
	c.LogID = p.LogId
	c.CloseTime = p.CloseTime.AsTime()
	c.FinalIndex = p.FinalIndex

	if len(p.FinalTagV) != 32 {
		return c, fmt.Errorf("invalid FinalTagV size: expected 32, got %d", len(p.FinalTagV))
	}
	copy(c.FinalTagV[:], p.FinalTagV)

	if len(p.FinalTagT) != 32 {
		return c, fmt.Errorf("invalid FinalTagT size: expected 32, got %d", len(p.FinalTagT))
	}
	copy(c.FinalTagT[:], p.FinalTagT)

	return c, nil
}

// ToProtoRecord converts Record to protobuf message
func ToProtoRecord(r Record) *pb.Record {
	return &pb.Record{
		Index: r.Index,
		Ts:    r.TS,
		Msg:   r.Msg,
		TagV:  r.TagV[:],
		TagT:  r.TagT[:],
	}
}

// FromProtoRecord converts protobuf message to Record
func FromProtoRecord(p *pb.Record) (Record, error) {
	var r Record
	r.Index = p.Index
	r.TS = p.Ts
	r.Msg = append([]byte(nil), p.Msg...)

	if len(p.TagV) != 32 {
		return r, fmt.Errorf("invalid TagV size: expected 32, got %d", len(p.TagV))
	}
	copy(r.TagV[:], p.TagV)

	if len(p.TagT) != 32 {
		return r, fmt.Errorf("invalid TagT size: expected 32, got %d", len(p.TagT))
	}
	copy(r.TagT[:], p.TagT)

	return r, nil
}

// ToProtoRecords converts a slice of Records to protobuf messages
func ToProtoRecords(records []Record) []*pb.Record {
	result := make([]*pb.Record, len(records))
	for i, r := range records {
		result[i] = ToProtoRecord(r)
	}
	return result
}

// FromProtoRecords converts protobuf messages to a slice of Records
func FromProtoRecords(pRecords []*pb.Record) ([]Record, error) {
	result := make([]Record, len(pRecords))
	for i, p := range pRecords {
		r, err := FromProtoRecord(p)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		result[i] = r
	}
	return result, nil
}
