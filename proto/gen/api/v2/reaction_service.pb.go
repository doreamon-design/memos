// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: api/v2/reaction_service.proto

package apiv2

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Reaction_Type int32

const (
	Reaction_TYPE_UNSPECIFIED Reaction_Type = 0
	Reaction_THUMBS_UP        Reaction_Type = 1
	Reaction_THUMBS_DOWN      Reaction_Type = 2
	Reaction_HEART            Reaction_Type = 3
	Reaction_FIRE             Reaction_Type = 4
	Reaction_CLAPPING_HANDS   Reaction_Type = 5
	Reaction_LAUGH            Reaction_Type = 6
	Reaction_OK_HAND          Reaction_Type = 7
	Reaction_ROCKET           Reaction_Type = 8
	Reaction_EYES             Reaction_Type = 9
	Reaction_THINKING_FACE    Reaction_Type = 10
	Reaction_CLOWN_FACE       Reaction_Type = 11
	Reaction_QUESTION_MARK    Reaction_Type = 12
)

// Enum value maps for Reaction_Type.
var (
	Reaction_Type_name = map[int32]string{
		0:  "TYPE_UNSPECIFIED",
		1:  "THUMBS_UP",
		2:  "THUMBS_DOWN",
		3:  "HEART",
		4:  "FIRE",
		5:  "CLAPPING_HANDS",
		6:  "LAUGH",
		7:  "OK_HAND",
		8:  "ROCKET",
		9:  "EYES",
		10: "THINKING_FACE",
		11: "CLOWN_FACE",
		12: "QUESTION_MARK",
	}
	Reaction_Type_value = map[string]int32{
		"TYPE_UNSPECIFIED": 0,
		"THUMBS_UP":        1,
		"THUMBS_DOWN":      2,
		"HEART":            3,
		"FIRE":             4,
		"CLAPPING_HANDS":   5,
		"LAUGH":            6,
		"OK_HAND":          7,
		"ROCKET":           8,
		"EYES":             9,
		"THINKING_FACE":    10,
		"CLOWN_FACE":       11,
		"QUESTION_MARK":    12,
	}
)

func (x Reaction_Type) Enum() *Reaction_Type {
	p := new(Reaction_Type)
	*p = x
	return p
}

func (x Reaction_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Reaction_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_api_v2_reaction_service_proto_enumTypes[0].Descriptor()
}

func (Reaction_Type) Type() protoreflect.EnumType {
	return &file_api_v2_reaction_service_proto_enumTypes[0]
}

func (x Reaction_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Reaction_Type.Descriptor instead.
func (Reaction_Type) EnumDescriptor() ([]byte, []int) {
	return file_api_v2_reaction_service_proto_rawDescGZIP(), []int{0, 0}
}

type Reaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id int32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	// The name of the creator.
	// Format: users/{id}
	Creator      string        `protobuf:"bytes,2,opt,name=creator,proto3" json:"creator,omitempty"`
	ContentId    string        `protobuf:"bytes,3,opt,name=content_id,json=contentId,proto3" json:"content_id,omitempty"`
	ReactionType Reaction_Type `protobuf:"varint,4,opt,name=reaction_type,json=reactionType,proto3,enum=memos.api.v2.Reaction_Type" json:"reaction_type,omitempty"`
}

func (x *Reaction) Reset() {
	*x = Reaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v2_reaction_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Reaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Reaction) ProtoMessage() {}

func (x *Reaction) ProtoReflect() protoreflect.Message {
	mi := &file_api_v2_reaction_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Reaction.ProtoReflect.Descriptor instead.
func (*Reaction) Descriptor() ([]byte, []int) {
	return file_api_v2_reaction_service_proto_rawDescGZIP(), []int{0}
}

func (x *Reaction) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Reaction) GetCreator() string {
	if x != nil {
		return x.Creator
	}
	return ""
}

func (x *Reaction) GetContentId() string {
	if x != nil {
		return x.ContentId
	}
	return ""
}

func (x *Reaction) GetReactionType() Reaction_Type {
	if x != nil {
		return x.ReactionType
	}
	return Reaction_TYPE_UNSPECIFIED
}

var File_api_v2_reaction_service_proto protoreflect.FileDescriptor

var file_api_v2_reaction_service_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x72, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0c, 0x6d, 0x65, 0x6d, 0x6f, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x22, 0xe1, 0x02,
	0x0a, 0x08, 0x52, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x02, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x6f, 0x72, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x49, 0x64, 0x12, 0x40, 0x0a, 0x0d, 0x72, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1b, 0x2e, 0x6d, 0x65, 0x6d,
	0x6f, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x52, 0x65, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0c, 0x72, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x54, 0x79, 0x70, 0x65, 0x22, 0xc9, 0x01, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x14,
	0x0a, 0x10, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49,
	0x45, 0x44, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x54, 0x48, 0x55, 0x4d, 0x42, 0x53, 0x5f, 0x55,
	0x50, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x54, 0x48, 0x55, 0x4d, 0x42, 0x53, 0x5f, 0x44, 0x4f,
	0x57, 0x4e, 0x10, 0x02, 0x12, 0x09, 0x0a, 0x05, 0x48, 0x45, 0x41, 0x52, 0x54, 0x10, 0x03, 0x12,
	0x08, 0x0a, 0x04, 0x46, 0x49, 0x52, 0x45, 0x10, 0x04, 0x12, 0x12, 0x0a, 0x0e, 0x43, 0x4c, 0x41,
	0x50, 0x50, 0x49, 0x4e, 0x47, 0x5f, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x10, 0x05, 0x12, 0x09, 0x0a,
	0x05, 0x4c, 0x41, 0x55, 0x47, 0x48, 0x10, 0x06, 0x12, 0x0b, 0x0a, 0x07, 0x4f, 0x4b, 0x5f, 0x48,
	0x41, 0x4e, 0x44, 0x10, 0x07, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x4f, 0x43, 0x4b, 0x45, 0x54, 0x10,
	0x08, 0x12, 0x08, 0x0a, 0x04, 0x45, 0x59, 0x45, 0x53, 0x10, 0x09, 0x12, 0x11, 0x0a, 0x0d, 0x54,
	0x48, 0x49, 0x4e, 0x4b, 0x49, 0x4e, 0x47, 0x5f, 0x46, 0x41, 0x43, 0x45, 0x10, 0x0a, 0x12, 0x0e,
	0x0a, 0x0a, 0x43, 0x4c, 0x4f, 0x57, 0x4e, 0x5f, 0x46, 0x41, 0x43, 0x45, 0x10, 0x0b, 0x12, 0x11,
	0x0a, 0x0d, 0x51, 0x55, 0x45, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4d, 0x41, 0x52, 0x4b, 0x10,
	0x0c, 0x42, 0xac, 0x01, 0x0a, 0x10, 0x63, 0x6f, 0x6d, 0x2e, 0x6d, 0x65, 0x6d, 0x6f, 0x73, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x42, 0x14, 0x52, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x30,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x75, 0x73, 0x65, 0x6d, 0x65,
	0x6d, 0x6f, 0x73, 0x2f, 0x6d, 0x65, 0x6d, 0x6f, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x65, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x3b, 0x61, 0x70, 0x69, 0x76, 0x32,
	0xa2, 0x02, 0x03, 0x4d, 0x41, 0x58, 0xaa, 0x02, 0x0c, 0x4d, 0x65, 0x6d, 0x6f, 0x73, 0x2e, 0x41,
	0x70, 0x69, 0x2e, 0x56, 0x32, 0xca, 0x02, 0x0c, 0x4d, 0x65, 0x6d, 0x6f, 0x73, 0x5c, 0x41, 0x70,
	0x69, 0x5c, 0x56, 0x32, 0xe2, 0x02, 0x18, 0x4d, 0x65, 0x6d, 0x6f, 0x73, 0x5c, 0x41, 0x70, 0x69,
	0x5c, 0x56, 0x32, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea,
	0x02, 0x0e, 0x4d, 0x65, 0x6d, 0x6f, 0x73, 0x3a, 0x3a, 0x41, 0x70, 0x69, 0x3a, 0x3a, 0x56, 0x32,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_v2_reaction_service_proto_rawDescOnce sync.Once
	file_api_v2_reaction_service_proto_rawDescData = file_api_v2_reaction_service_proto_rawDesc
)

func file_api_v2_reaction_service_proto_rawDescGZIP() []byte {
	file_api_v2_reaction_service_proto_rawDescOnce.Do(func() {
		file_api_v2_reaction_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v2_reaction_service_proto_rawDescData)
	})
	return file_api_v2_reaction_service_proto_rawDescData
}

var file_api_v2_reaction_service_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_v2_reaction_service_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_api_v2_reaction_service_proto_goTypes = []interface{}{
	(Reaction_Type)(0), // 0: memos.api.v2.Reaction.Type
	(*Reaction)(nil),   // 1: memos.api.v2.Reaction
}
var file_api_v2_reaction_service_proto_depIdxs = []int32{
	0, // 0: memos.api.v2.Reaction.reaction_type:type_name -> memos.api.v2.Reaction.Type
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_api_v2_reaction_service_proto_init() }
func file_api_v2_reaction_service_proto_init() {
	if File_api_v2_reaction_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_v2_reaction_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Reaction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_v2_reaction_service_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_v2_reaction_service_proto_goTypes,
		DependencyIndexes: file_api_v2_reaction_service_proto_depIdxs,
		EnumInfos:         file_api_v2_reaction_service_proto_enumTypes,
		MessageInfos:      file_api_v2_reaction_service_proto_msgTypes,
	}.Build()
	File_api_v2_reaction_service_proto = out.File
	file_api_v2_reaction_service_proto_rawDesc = nil
	file_api_v2_reaction_service_proto_goTypes = nil
	file_api_v2_reaction_service_proto_depIdxs = nil
}
