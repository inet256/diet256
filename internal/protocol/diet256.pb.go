// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.22.2
// source: diet256.proto

package protocol

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

type FindAddrReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Prefix []byte `protobuf:"bytes,1,opt,name=prefix,proto3" json:"prefix,omitempty"`
	Nbits  int32  `protobuf:"varint,2,opt,name=nbits,proto3" json:"nbits,omitempty"`
}

func (x *FindAddrReq) Reset() {
	*x = FindAddrReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindAddrReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindAddrReq) ProtoMessage() {}

func (x *FindAddrReq) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindAddrReq.ProtoReflect.Descriptor instead.
func (*FindAddrReq) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{0}
}

func (x *FindAddrReq) GetPrefix() []byte {
	if x != nil {
		return x.Prefix
	}
	return nil
}

func (x *FindAddrReq) GetNbits() int32 {
	if x != nil {
		return x.Nbits
	}
	return 0
}

type FindAddrRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addr []byte `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (x *FindAddrRes) Reset() {
	*x = FindAddrRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindAddrRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindAddrRes) ProtoMessage() {}

func (x *FindAddrRes) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindAddrRes.ProtoReflect.Descriptor instead.
func (*FindAddrRes) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{1}
}

func (x *FindAddrRes) GetAddr() []byte {
	if x != nil {
		return x.Addr
	}
	return nil
}

type LookupPublicKeyReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Target []byte `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
}

func (x *LookupPublicKeyReq) Reset() {
	*x = LookupPublicKeyReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LookupPublicKeyReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LookupPublicKeyReq) ProtoMessage() {}

func (x *LookupPublicKeyReq) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LookupPublicKeyReq.ProtoReflect.Descriptor instead.
func (*LookupPublicKeyReq) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{2}
}

func (x *LookupPublicKeyReq) GetTarget() []byte {
	if x != nil {
		return x.Target
	}
	return nil
}

type LookupPublicKeyRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicKey []byte `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *LookupPublicKeyRes) Reset() {
	*x = LookupPublicKeyRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LookupPublicKeyRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LookupPublicKeyRes) ProtoMessage() {}

func (x *LookupPublicKeyRes) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LookupPublicKeyRes.ProtoReflect.Descriptor instead.
func (*LookupPublicKeyRes) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{3}
}

func (x *LookupPublicKeyRes) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

type DialReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Target []byte `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
}

func (x *DialReq) Reset() {
	*x = DialReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DialReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DialReq) ProtoMessage() {}

func (x *DialReq) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DialReq.ProtoReflect.Descriptor instead.
func (*DialReq) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{4}
}

func (x *DialReq) GetTarget() []byte {
	if x != nil {
		return x.Target
	}
	return nil
}

type DialRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addr string `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (x *DialRes) Reset() {
	*x = DialRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DialRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DialRes) ProtoMessage() {}

func (x *DialRes) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DialRes.ProtoReflect.Descriptor instead.
func (*DialRes) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{5}
}

func (x *DialRes) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

type ListenReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ListenReq) Reset() {
	*x = ListenReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListenReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListenReq) ProtoMessage() {}

func (x *ListenReq) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListenReq.ProtoReflect.Descriptor instead.
func (*ListenReq) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{6}
}

type ListenRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id   []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Addr string `protobuf:"bytes,2,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (x *ListenRes) Reset() {
	*x = ListenRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_diet256_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListenRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListenRes) ProtoMessage() {}

func (x *ListenRes) ProtoReflect() protoreflect.Message {
	mi := &file_diet256_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListenRes.ProtoReflect.Descriptor instead.
func (*ListenRes) Descriptor() ([]byte, []int) {
	return file_diet256_proto_rawDescGZIP(), []int{7}
}

func (x *ListenRes) GetId() []byte {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *ListenRes) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

var File_diet256_proto protoreflect.FileDescriptor

var file_diet256_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x64, 0x69, 0x65, 0x74, 0x32, 0x35, 0x36, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x64, 0x69, 0x65, 0x74, 0x32, 0x35, 0x36, 0x22, 0x3b, 0x0a, 0x0b, 0x46, 0x69, 0x6e, 0x64,
	0x41, 0x64, 0x64, 0x72, 0x52, 0x65, 0x71, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69,
	0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12,
	0x14, 0x0a, 0x05, 0x6e, 0x62, 0x69, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05,
	0x6e, 0x62, 0x69, 0x74, 0x73, 0x22, 0x21, 0x0a, 0x0b, 0x46, 0x69, 0x6e, 0x64, 0x41, 0x64, 0x64,
	0x72, 0x52, 0x65, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x61, 0x64, 0x64, 0x72, 0x22, 0x2c, 0x0a, 0x12, 0x4c, 0x6f, 0x6f, 0x6b,
	0x75, 0x70, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x12, 0x16,
	0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x22, 0x33, 0x0a, 0x12, 0x4c, 0x6f, 0x6f, 0x6b, 0x75, 0x70,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x12, 0x1d, 0x0a, 0x0a,
	0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x21, 0x0a, 0x07, 0x44,
	0x69, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x22, 0x1d,
	0x0a, 0x07, 0x44, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x64, 0x64,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x64, 0x64, 0x72, 0x22, 0x0b, 0x0a,
	0x09, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x22, 0x2f, 0x0a, 0x09, 0x4c, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x64, 0x64, 0x72, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x64, 0x64, 0x72, 0x32, 0xf6, 0x01, 0x0a, 0x07,
	0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x12, 0x38, 0x0a, 0x08, 0x46, 0x69, 0x6e, 0x64, 0x41,
	0x64, 0x64, 0x72, 0x12, 0x14, 0x2e, 0x64, 0x69, 0x65, 0x74, 0x32, 0x35, 0x36, 0x2e, 0x46, 0x69,
	0x6e, 0x64, 0x41, 0x64, 0x64, 0x72, 0x52, 0x65, 0x71, 0x1a, 0x14, 0x2e, 0x64, 0x69, 0x65, 0x74,
	0x32, 0x35, 0x36, 0x2e, 0x46, 0x69, 0x6e, 0x64, 0x41, 0x64, 0x64, 0x72, 0x52, 0x65, 0x73, 0x22,
	0x00, 0x12, 0x4d, 0x0a, 0x0f, 0x4c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x12, 0x1b, 0x2e, 0x64, 0x69, 0x65, 0x74, 0x32, 0x35, 0x36, 0x2e, 0x4c,
	0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x1a, 0x1b, 0x2e, 0x64, 0x69, 0x65, 0x74, 0x32, 0x35, 0x36, 0x2e, 0x4c, 0x6f, 0x6f, 0x6b,
	0x75, 0x70, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x22, 0x00,
	0x12, 0x2c, 0x0a, 0x04, 0x44, 0x69, 0x61, 0x6c, 0x12, 0x10, 0x2e, 0x64, 0x69, 0x65, 0x74, 0x32,
	0x35, 0x36, 0x2e, 0x44, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x1a, 0x10, 0x2e, 0x64, 0x69, 0x65,
	0x74, 0x32, 0x35, 0x36, 0x2e, 0x44, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x34,
	0x0a, 0x06, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x12, 0x12, 0x2e, 0x64, 0x69, 0x65, 0x74, 0x32,
	0x35, 0x36, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x1a, 0x12, 0x2e, 0x64,
	0x69, 0x65, 0x74, 0x32, 0x35, 0x36, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x52, 0x65, 0x73,
	0x22, 0x00, 0x30, 0x01, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x69, 0x6e, 0x65, 0x74, 0x32, 0x35, 0x36, 0x2f, 0x64, 0x69, 0x65, 0x74, 0x32,
	0x35, 0x36, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_diet256_proto_rawDescOnce sync.Once
	file_diet256_proto_rawDescData = file_diet256_proto_rawDesc
)

func file_diet256_proto_rawDescGZIP() []byte {
	file_diet256_proto_rawDescOnce.Do(func() {
		file_diet256_proto_rawDescData = protoimpl.X.CompressGZIP(file_diet256_proto_rawDescData)
	})
	return file_diet256_proto_rawDescData
}

var file_diet256_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_diet256_proto_goTypes = []interface{}{
	(*FindAddrReq)(nil),        // 0: diet256.FindAddrReq
	(*FindAddrRes)(nil),        // 1: diet256.FindAddrRes
	(*LookupPublicKeyReq)(nil), // 2: diet256.LookupPublicKeyReq
	(*LookupPublicKeyRes)(nil), // 3: diet256.LookupPublicKeyRes
	(*DialReq)(nil),            // 4: diet256.DialReq
	(*DialRes)(nil),            // 5: diet256.DialRes
	(*ListenReq)(nil),          // 6: diet256.ListenReq
	(*ListenRes)(nil),          // 7: diet256.ListenRes
}
var file_diet256_proto_depIdxs = []int32{
	0, // 0: diet256.Control.FindAddr:input_type -> diet256.FindAddrReq
	2, // 1: diet256.Control.LookupPublicKey:input_type -> diet256.LookupPublicKeyReq
	4, // 2: diet256.Control.Dial:input_type -> diet256.DialReq
	6, // 3: diet256.Control.Listen:input_type -> diet256.ListenReq
	1, // 4: diet256.Control.FindAddr:output_type -> diet256.FindAddrRes
	3, // 5: diet256.Control.LookupPublicKey:output_type -> diet256.LookupPublicKeyRes
	5, // 6: diet256.Control.Dial:output_type -> diet256.DialRes
	7, // 7: diet256.Control.Listen:output_type -> diet256.ListenRes
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_diet256_proto_init() }
func file_diet256_proto_init() {
	if File_diet256_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_diet256_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindAddrReq); i {
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
		file_diet256_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindAddrRes); i {
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
		file_diet256_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LookupPublicKeyReq); i {
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
		file_diet256_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LookupPublicKeyRes); i {
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
		file_diet256_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DialReq); i {
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
		file_diet256_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DialRes); i {
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
		file_diet256_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListenReq); i {
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
		file_diet256_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListenRes); i {
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
			RawDescriptor: file_diet256_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_diet256_proto_goTypes,
		DependencyIndexes: file_diet256_proto_depIdxs,
		MessageInfos:      file_diet256_proto_msgTypes,
	}.Build()
	File_diet256_proto = out.File
	file_diet256_proto_rawDesc = nil
	file_diet256_proto_goTypes = nil
	file_diet256_proto_depIdxs = nil
}
