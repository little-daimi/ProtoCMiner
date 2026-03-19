import idaapi
import ida_idaapi
import idautils
import ida_bytes
import ida_ida
import ida_search
import ida_segment
import ida_nalt
import ida_typeinf
import os
from enum import IntEnum

class ProtobufCLabel(IntEnum):
    REQUIRED = 0
    OPTIONAL = 1
    REPEATED = 2
    NONE = 3

    def to_string(self):
        return "" if self == self.NONE else self.name.lower()

class ProtobufCType(IntEnum):
    INT32 = 0
    SINT32 = 1
    SFIXED32 = 2
    INT64 = 3
    SINT64 = 4
    SFIXED64 = 5
    UINT32 = 6
    FIXED32 = 7
    UINT64 = 8
    FIXED64 = 9
    FLOAT = 10
    DOUBLE = 11
    BOOL = 12
    ENUM = 13
    STRING = 14
    BYTES = 15
    MESSAGE = 16

    def to_string(self):
        return self.name.lower()

# ----------------- C 语言结构体与枚举定义注入 -----------------
PROTOBUF_C_TYPES_DECL = """
typedef enum {
    PROTOBUF_C_FIELD_FLAG_PACKED = (1 << 0),
    PROTOBUF_C_FIELD_FLAG_DEPRECATED = (1 << 1),
    PROTOBUF_C_FIELD_FLAG_ONEOF = (1 << 2),
} ProtobufCFieldFlag;

typedef enum {
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_LABEL_NONE,
} ProtobufCLabel;

typedef enum {
    PROTOBUF_C_TYPE_INT32,
    PROTOBUF_C_TYPE_SINT32,
    PROTOBUF_C_TYPE_SFIXED32,
    PROTOBUF_C_TYPE_INT64,
    PROTOBUF_C_TYPE_SINT64,
    PROTOBUF_C_TYPE_SFIXED64,
    PROTOBUF_C_TYPE_UINT32,
    PROTOBUF_C_TYPE_FIXED32,
    PROTOBUF_C_TYPE_UINT64,
    PROTOBUF_C_TYPE_FIXED64,
    PROTOBUF_C_TYPE_FLOAT,
    PROTOBUF_C_TYPE_DOUBLE,
    PROTOBUF_C_TYPE_BOOL,
    PROTOBUF_C_TYPE_ENUM,
    PROTOBUF_C_TYPE_STRING,
    PROTOBUF_C_TYPE_BYTES,
    PROTOBUF_C_TYPE_MESSAGE,
} ProtobufCType;

struct ProtobufCFieldDescriptor;
struct ProtobufCMessageDescriptor {
    unsigned int magic;
    const char *name;
    const char *short_name;
    const char *c_name;
    const char *packagename;
    void* sizeof_message;
    unsigned int n_fields;
    const struct ProtobufCFieldDescriptor *fields;
    unsigned int n_field_ranges;
    const void *message_field_ranges;
    void *message_init;
    void *reserved1;
    void *reserved2;
    void *reserved3;
};

struct ProtobufCFieldDescriptor {
    const char *name;
    unsigned int id;
    ProtobufCLabel label;
    ProtobufCType type;
    unsigned int quantifier_offset;
    unsigned int offset;
    const void *descriptor;
    const void *default_value;
    unsigned int flags;
    unsigned int reserved_flags;
    void *reserved2;
    void *reserved3;
};

struct ProtobufCEnumValue {
    const char *name;
    const char *c_name;
    int value;
};

struct ProtobufCEnumDescriptor {
    unsigned int magic;
    const char *name;
    const char *short_name;
    const char *c_name;
    const char *packagename;
    unsigned int n_values;
    const struct ProtobufCEnumValue *values;
    unsigned int n_values_by_name;
    const void *values_by_name;
    unsigned int n_value_ranges;
    const void *value_ranges;
    void *reserved1;
    void *reserved2;
    void *reserved3;
    void *reserved4;
};
"""

class ProtoNode():
    def __init__(self):
        self.child = {}
        self.fields = {}
        self.name = ""
        self.type = "root"
        self.label = ""
        self.id = 0
    

class ProtoCMiner(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Automatically reverse proto-c and dump .proto file"
    help = "Press Ctrl+R to run the plugin"
    wanted_name = "ProtoCMiner"
    wanted_hotkey = "Ctrl-R"

    # 用于保存整个 proto 结构的树
    proto_tree = ProtoNode()
    parsed_messages = set()
    parsed_enums = set()
    types_loaded = 0

    def init(self): 
        self.is_64bit = idaapi.inf_is_64bit()
        self.size_t = 8 if self.is_64bit else 4
        self.endian = 'big' if idaapi.inf_is_be() else 'little'
        return idaapi.PLUGIN_OK

    def term(self):
        pass

    def parse_size_t(self, ea):
        return ida_bytes.get_qword(ea) if self.is_64bit else ida_bytes.get_dword(ea)

    def parse_str(self, ea):
        if ea == idaapi.BADADDR or ida_segment.getseg(ea) is None:
            return "unknown"
            
        strlen = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C, ida_bytes.ALOPT_IGNHEADS)
        if strlen <= 0:
            return "unknown"
        
        raw_bytes = ida_bytes.get_bytes(ea, strlen)
        if raw_bytes:
            try:
                return bytes(raw_bytes).rstrip(b'\x00').decode('utf-8', errors='ignore')
            except Exception:
                if isinstance(raw_bytes, str):
                    return raw_bytes.replace('\x00', '')
                return "unknown"
        return "unknown"

    def setup_types(self): 
        """
        初始化proto-c要用的类型
        初始化失败时候返回False
        """
        if not self.types_loaded:
            errors = ida_typeinf.idc_parse_types(PROTOBUF_C_TYPES_DECL, ida_typeinf.HTI_PAKDEF)
            if errors != 0:
                print(f"[!] Warning: idc_parse_types returned {errors}, types might already exist or parsing failed.")
                return False
            self.types_loaded = 1
        return True
        
    def apply_struct(self, ea, struct_name):
        """
        根据类型名字，在地址ea处应用类型
        应用失败时返回False
        """
        tif = ida_typeinf.tinfo_t()
        idati = ida_typeinf.get_idati()
        
        if tif.get_named_type(idati, struct_name):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, tif.get_size())
            ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            return True
        return False

    def insert_object(self, object : str):
        """
        接收类如`ctf.test.UserRecord`的串
        将其按照`.`切割后，逐个插入`self.proto_tree`里面，设置名字，并返回最后一个节点
        """
        object_chain = object.split(".")
        cursor = self.proto_tree
        for node_name in object_chain:
            if node_name not in cursor.child:
                cursor.child[node_name] = ProtoNode()
                cursor.child[node_name].name = node_name
            cursor = cursor.child[node_name]
        return cursor

    def parse_enum(self, ea):
        """
        尝试从地址ea处parse一个enum并写入self.proto_tree内
        """
        if ea == 0 or ea == idaapi.BADADDR:
            return None
        if ea in self.parsed_enums or ea == 0: # 防止重复解析
            return
        self.parsed_enums.add(ea)  
        self.apply_struct(ea, "ProtobufCEnumDescriptor")

        # 直接计算偏移拿到需要的信息
        name_ptr = self.parse_size_t(ea + self.size_t)
        enum_name = self.parse_str(name_ptr)
        
        n_values_offset = self.size_t * 5
        n_values = ida_bytes.get_wide_dword(ea + n_values_offset)
        values_ptr = self.parse_size_t(ea + n_values_offset + 4 + (4 if self.is_64bit else 0))
        enum_val_size = self.size_t * 3

        node = self.insert_object(enum_name)
        node.type = "enum"
        
        # 遍历所有枚举值
        for i in range(n_values):
            val_ea = values_ptr + i * enum_val_size
            self.apply_struct(val_ea, "ProtobufCEnumValue")
            
            v_name_ptr = self.parse_size_t(val_ea)
            v_name = self.parse_str(v_name_ptr)
            v_val = ida_bytes.get_wide_dword(val_ea + self.size_t * 2)
            if v_val > 0x7FFFFFFF:
                v_val -= 0x100000000
                
            node.fields[v_name] = {"id": v_val}
        

    def parse_proto(self, ea):
        if ea == 0 or ea == idaapi.BADADDR:
            return None
        if not self.setup_types():
            return None
        if ea in self.parsed_messages: # 防止重复解析
            return None
        self.parsed_messages.add(ea)
        self.apply_struct(ea, "ProtobufCMessageDescriptor")

        # 直接从偏移里面把需要的信息拿出来
        message_name = self.parse_str(self.parse_size_t(ea + self.size_t))
        n_fields = ida_bytes.get_wide_dword(ea + self.size_t * 6)
        fields_ptr = self.parse_size_t(ea + self.size_t * 7)

        field_size = 72 if self.is_64bit else 48

        node = self.insert_object(message_name)
        node.type = "message"

        # 遍历所有字段 n_fields
        for i in range(n_fields):
            f_ea = fields_ptr + (i * field_size)
            self.apply_struct(f_ea, "ProtobufCFieldDescriptor")

            f_name = self.parse_str(self.parse_size_t(f_ea))
            
            f_id_off = self.size_t
            f_id = ida_bytes.get_wide_dword(f_ea + f_id_off)
            f_label_val = ida_bytes.get_wide_dword(f_ea + f_id_off + 4)
            f_type_val = ida_bytes.get_wide_dword(f_ea + f_id_off + 8)
            f_desc_off = 32 if self.is_64bit else 24
            f_desc_ptr = self.parse_size_t(f_ea + f_desc_off)
            
            # 获得字段label
            try:
                label_enum = ProtobufCLabel(f_label_val)
                label_str = label_enum.to_string()
            except ValueError:
                label_enum = None
                label_str = f"unknown_label_{f_label_val}"

            # 获得字段type
            try:
                type_enum = ProtobufCType(f_type_val)
                type_str = type_enum.to_string()
            except ValueError:
                type_enum = None
                type_str = f"unknown_type_{f_type_val}"

            # 如果是message，尝试递归parse message
            if type_enum == ProtobufCType.MESSAGE and f_desc_ptr != 0: 
                self.parse_proto(f_desc_ptr)
                child_name_ptr_off = self.size_t
                type_str = self.parse_str(self.parse_size_t(f_desc_ptr + child_name_ptr_off))

            # 如果是enum，尝试parse enum
            elif type_enum == ProtobufCType.ENUM and f_desc_ptr != 0: 
                self.parse_enum(f_desc_ptr)
                child_name_ptr_off = self.size_t
                type_str = self.parse_str(self.parse_size_t(f_desc_ptr + child_name_ptr_off))
            
            # 注意虽然 .proto 的定义不能含有 `.`，但是 .proto 引用其他类型的时候可以含有 .
            # 所以这里不用 type_str = type_str.split('.')[-1] 来处理

            # 跨包引用的时候需要`.``
            # 如果没有`.`，protoc就没办法区分这是相对路径还是绝对路径
            if type_enum == ProtobufCType.MESSAGE or type_enum == ProtobufCType.ENUM:
                type_str = '.' + type_str

            node.fields[f_name] = {
                "label": label_str,
                "type": type_str,
                "id": f_id
            }
    def render_tree(self, node, indent_level=0):
        """渲染单个节点"""
        res = ""
        indent = "    " * indent_level
        
        # 1. 如果是 Enum
        if node.type == "enum":
            res += f"{indent}enum {node.name} {{\n"
            for fname, fprops in node.fields.items():
                res += f"{indent}    {fname} = {fprops['id']};\n"
            res += f"{indent}}}\n"
            
        # 2. 如果是 Message 或 未被收拢的中间 namespace
        else:
            res += f"{indent}message {node.name} {{\n"
            
            # 先渲染嵌套的子节点
            for child in node.child.values():
                res += self.render_tree(child, indent_level + 1)
                
            # 再渲染自己的字段
            for fname, fprops in node.fields.items():
                label = fprops.get('label', '')
                label_str = label + " " if label else ""
                type_str = fprops.get('type', 'unknown')
                res += f"{indent}    {label_str}{type_str} {fname} = {fprops['id']};\n"
                
            res += f"{indent}}}\n"
            
        return res

    def generate_proto_text(self):
        """遍历所有节点，并返回.proto文件"""
        cursor = self.proto_tree
        pkg_parts = []
        
        # 只要只有一个子节点，并且没有任何字段，就收拢为 package
        while len(cursor.child) == 1 and not cursor.fields:
            child_name, child_node = list(cursor.child.items())[0]
            if child_node.type in ["message", "enum"]:
                break
                
            pkg_parts.append(child_name)
            cursor = child_node
            
        output = ['syntax = "proto2";\n']

        # 在结果的开头添加package
        if pkg_parts:
            output.append(f"package {'.'.join(pkg_parts)};\n")
            
        for child in cursor.child.values():
            output.append(self.render_tree(child, 0))
            
        return "\n".join(output)

    def run(self, arg):

        self.parsed_enums = set()
        self.parsed_messages = set()
        self.proto_tree = ProtoNode()

        PROTO_MSG_MAGIC = 0x28aaeef9.to_bytes(self.size_t, byteorder=self.endian)
        
        # 获得所有段的地址
        segs = idautils.Segments()
        
        # 遍历所有段寻找魔数
        for seg in segs:
            segment = ida_segment.getseg(seg)
            if not segment:
                continue
            start_addr = segment.start_ea
            end_addr = segment.end_ea
            
            # 在段内寻找所有可能的结构体（一个段内可能有多个结构体）
            while start_addr < end_addr:
                result = ida_bytes.find_bytes(
                    PROTO_MSG_MAGIC,
                    start_addr,
                    end_addr - start_addr,
                    flags = idaapi.SEARCH_DOWN
                )
                if result == idaapi.BADADDR:
                    break
                print(f"Magic Found at: {result}")
                start_addr = result + 4
                self.parse_proto(result)

        # 序列化结果并dump到.proto里面
        out_text = self.generate_proto_text()
        print(out_text)

        input_file_path = ida_nalt.get_input_file_path()
        if input_file_path:
            out_dir = os.path.dirname(input_file_path)
            out_path = os.path.join(out_dir, "dump.proto")
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(out_text)
                print(f"\n[+] Successfully saved proto definitions to: {out_path}")
            except Exception as e:
                print(f"\n[-] Failed to write dump.proto: {e}")
        else:
            print("\n[-] Could not determine input file path to save dump.proto")

def PLUGIN_ENTRY():
    return ProtoCMiner()