/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 Marek Cingel */

/*
 * TestLab reference adapter over asn1c-generated code. It hides the generated C types
 * behind a line protocol, so nothing else in TestLab includes asn1c headers.
 *
 * Each stdin line is one request, five fields separated by single spaces:
 *
 *     ID TYPE DECODE ENCODE HEX
 *
 * DECODE is ber, der or cer; ENCODE is ber, der, cer or none; HEX is the wire in
 * lowercase hex, or "-" for empty input. stdout receives JSON lines: the identity,
 * then one flushed result per request. A request this adapter cannot represent is a
 * protocol error: it exits with code 2, so the run fails instead of reporting a result.
 *
 * setup_asn1c.py compiles this file with the generated sources and defines
 * TESTLAB_ASN1C_VERSION, TESTLAB_SCHEMA and TESTLAB_SCHEMA_SHA256, and writes
 * testlab_types.h, an X-macro list of the schema's type names.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asn_application.h"
#include "asn_internal.h"
#include "BIT_STRING.h"
#include "BOOLEAN.h"
#include "IA5String.h"
#include "INTEGER.h"
#include "NULL.h"
#include "OBJECT_IDENTIFIER.h"
#include "OCTET_STRING.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_CHOICE.h"
#include "constr_SEQUENCE.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SET.h"
#include "constr_SET_OF.h"

#define TESTLAB_TYPE(name) extern asn_TYPE_descriptor_t asn_DEF_##name;
#include "testlab_types.h"
#undef TESTLAB_TYPE

static const struct {
    const char *name;
    asn_TYPE_descriptor_t *descriptor;
} types[] = {
#define TESTLAB_TYPE(name) {#name, &asn_DEF_##name},
#include "testlab_types.h"
#undef TESTLAB_TYPE
};

#define TYPE_COUNT (sizeof(types) / sizeof(types[0]))
#define MAX_WIRE 4096
#define MAX_DEPTH 64

static const struct {
    const char *name;
    enum asn_transfer_syntax syntax;
} syntaxes[] = {{"ber", ATS_BER}, {"der", ATS_DER}, {"cer", ATS_CER}};

static void fail(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    fputs("asn1c adapter: ", stderr);
    vfprintf(stderr, format, arguments);
    fputc('\n', stderr);
    va_end(arguments);
    exit(2);
}

static void json_string(const char *text) {
    putchar('"');
    for(; *text; text++) {
        unsigned char c = (unsigned char)*text;
        if(c == '"' || c == '\\') printf("\\%c", c);
        else if(c < 0x20 || c > 0x7e) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static void json_hex(const uint8_t *buffer, size_t size) {
    size_t i;
    putchar('"');
    for(i = 0; i < size; i++) printf("%02x", buffer[i]);
    putchar('"');
}

/* Two's-complement content octets as a signed decimal string of any size. */
static void json_integer(const INTEGER_t *value) {
    size_t size = value->size, i, digits = 0;
    uint8_t *magnitude;
    char *text;
    int negative;
    if(size == 0) {
        fputs("null", stdout); /* No content octets: X.690 8.3.1 has no value for it. */
        return;
    }
    magnitude = malloc(size);
    text = malloc(size * 3 + 2);
    if(!magnitude || !text) fail("out of memory");
    memcpy(magnitude, value->buf, size);
    negative = (magnitude[0] & 0x80) != 0;
    if(negative) {
        unsigned carry = 1;
        for(i = size; i-- > 0;) {
            unsigned sum = (uint8_t)~magnitude[i] + carry;
            magnitude[i] = (uint8_t)sum;
            carry = sum >> 8;
        }
    }
    for(;;) {
        unsigned remainder = 0;
        int nonzero = 0;
        for(i = 0; i < size; i++) {
            unsigned current = remainder * 256 + magnitude[i];
            magnitude[i] = (uint8_t)(current / 10);
            remainder = current % 10;
            nonzero |= magnitude[i] != 0;
        }
        text[digits++] = (char)('0' + remainder);
        if(!nonzero) break;
    }
    if(negative) text[digits++] = '-';
    putchar('"');
    while(digits > 0) putchar(text[--digits]);
    putchar('"');
    free(magnitude);
    free(text);
}

static void json_oid(const OBJECT_IDENTIFIER_t *value) {
    asn_oid_arc_t fixed[32];
    asn_oid_arc_t *arcs = fixed;
    ssize_t count = OBJECT_IDENTIFIER_get_arcs(value, arcs, 32), i;
    if(count > 32) {
        arcs = malloc(sizeof(*arcs) * (size_t)count);
        if(!arcs) fail("out of memory");
        if(OBJECT_IDENTIFIER_get_arcs(value, arcs, (size_t)count) != count) fail("unstable OID arcs");
    }
    if(count < 0) {
        fputs("null", stdout); /* Malformed arcs or an arc above 2^32-1. */
    } else {
        putchar('"');
        for(i = 0; i < count; i++) printf(i ? ".%lu" : "%lu", (unsigned long)arcs[i]);
        putchar('"');
    }
    if(arcs != fixed) free(arcs);
}

static void json_value(const asn_TYPE_descriptor_t *td, const void *sptr, int depth);

static const void *member_pointer(const asn_TYPE_member_t *member, const void *sptr) {
    const void *address = (const char *)sptr + member->memb_offset;
    return (member->flags & ATF_POINTER) ? *(const void *const *)address : address;
}

static void json_fields(const asn_TYPE_descriptor_t *td, const void *sptr, int depth) {
    unsigned i;
    int first = 1;
    fputs(",\"fields\":[", stdout);
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        const void *field = member_pointer(member, sptr);
        if(!field) continue; /* An absent OPTIONAL member. */
        if(!first) putchar(',');
        first = 0;
        fputs("{\"name\":", stdout);
        json_string(member->name);
        fputs(",\"value\":", stdout);
        json_value(member->type, field, depth + 1);
        putchar('}');
    }
    putchar(']');
}

static void json_items(const asn_TYPE_descriptor_t *td, const void *sptr, int depth) {
    const asn_anonymous_sequence_ *list = _A_CSEQUENCE_FROM_VOID(sptr);
    int i;
    fputs(",\"items\":[", stdout);
    for(i = 0; i < list->count; i++) {
        if(i) putchar(',');
        json_value(td->elements[0].type, list->array[i], depth + 1);
    }
    putchar(']');
}

/* The typed value asn1c decoded, by kind; never the input bytes. */
static void json_value(const asn_TYPE_descriptor_t *td, const void *sptr, int depth) {
    const asn_TYPE_operation_t *op = td->op;
    if(depth > MAX_DEPTH) fail("value nests deeper than %d levels", MAX_DEPTH);
    fputs("{\"kind\":", stdout);
    if(op == &asn_OP_BOOLEAN) {
        fputs("\"boolean\",\"value\":", stdout);
        fputs(*(const BOOLEAN_t *)sptr ? "true" : "false", stdout);
    } else if(op == &asn_OP_INTEGER) {
        fputs("\"integer\",\"value\":", stdout);
        json_integer(sptr);
    } else if(op == &asn_OP_BIT_STRING) {
        const BIT_STRING_t *bits = sptr;
        printf("\"bit_string\",\"unused_bits\":%d,\"value\":", bits->bits_unused);
        json_hex(bits->buf, bits->size);
    } else if(op == &asn_OP_OCTET_STRING || op == &asn_OP_IA5String) {
        const OCTET_STRING_t *octets = sptr;
        fputs(op == &asn_OP_IA5String ? "\"ia5string\",\"value\":" : "\"octet_string\",\"value\":", stdout);
        json_hex(octets->buf, octets->size);
    } else if(op == &asn_OP_NULL) {
        fputs("\"null\"", stdout);
    } else if(op == &asn_OP_OBJECT_IDENTIFIER) {
        fputs("\"object_identifier\",\"value\":", stdout);
        json_oid(sptr);
    } else if(op == &asn_OP_SEQUENCE || op == &asn_OP_SET) {
        fputs(op == &asn_OP_SET ? "\"set\"" : "\"sequence\"", stdout);
        json_fields(td, sptr, depth);
    } else if(op == &asn_OP_SEQUENCE_OF || op == &asn_OP_SET_OF) {
        fputs(op == &asn_OP_SET_OF ? "\"set_of\"" : "\"sequence_of\"", stdout);
        json_items(td, sptr, depth);
    } else if(op == &asn_OP_CHOICE) {
        unsigned present = CHOICE_variant_get_presence(td, sptr);
        if(present == 0 || present > td->elements_count) fail("CHOICE %s has no alternative", td->name);
        fputs("\"choice\",\"alternative\":", stdout);
        json_string(td->elements[present - 1].name);
        fputs(",\"value\":", stdout);
        json_value(td->elements[present - 1].type,
                   member_pointer(&td->elements[present - 1], sptr), depth + 1);
    } else {
        fail("type %s has no TestLab representation", td->name);
    }
    putchar('}');
}

static int syntax_of(const char *name, enum asn_transfer_syntax *syntax) {
    size_t i;
    for(i = 0; i < sizeof(syntaxes) / sizeof(syntaxes[0]); i++) {
        if(strcmp(name, syntaxes[i].name) == 0) {
            *syntax = syntaxes[i].syntax;
            return 1;
        }
    }
    return 0;
}

static int nibble(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    fail("wire is not lowercase hex");
    return 0;
}

static size_t parse_hex(const char *hex, uint8_t *wire) {
    size_t length = strlen(hex), i;
    if(strcmp(hex, "-") == 0) return 0;
    if(length == 0 || length % 2 || length / 2 > MAX_WIRE) fail("wire must be 1-%d bytes of hex", MAX_WIRE);
    for(i = 0; i < length / 2; i++) wire[i] = (uint8_t)(nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]));
    return length / 2;
}

static void encode(const asn_TYPE_descriptor_t *td, const void *value, const char *name,
                   enum asn_transfer_syntax syntax) {
    asn_encode_to_new_buffer_result_t result;
    fputs(",\"encode\":{\"syntax\":", stdout);
    json_string(name);
    errno = 0;
    result = asn_encode_to_new_buffer(NULL, syntax, td, value);
    /* Its header promises a NULL buffer on failure, but 0.9.29 returns the scratch buffer
       anyway; only the encoded size tells success apart. */
    if(result.result.encoded >= 0) {
        fputs(",\"status\":\"encoded\",\"wire\":", stdout);
        json_hex(result.buffer, (size_t)result.result.encoded);
    } else if(errno == ENOENT) {
        fputs(",\"status\":\"unsupported\"", stdout); /* asn1c has no such encoder. */
    } else {
        fputs(",\"status\":\"failed\",\"detail\":", stdout);
        json_string(result.result.failed_type ? result.result.failed_type->name : "unknown type");
    }
    free(result.buffer);
    putchar('}');
}

static void handle(char *line) {
    static uint8_t wire[MAX_WIRE];
    char *fields[5], *rest = line;
    const asn_TYPE_descriptor_t *td = NULL;
    enum asn_transfer_syntax decode_syntax, encode_syntax = ATS_INVALID;
    void *value = NULL;
    asn_dec_rval_t rval;
    size_t size, i;
    for(i = 0; i < 5; i++) {
        fields[i] = rest;
        rest = strchr(rest, ' ');
        if((rest == NULL) != (i == 4)) fail("request needs exactly five fields");
        if(rest) *rest++ = '\0';
    }
    for(i = 0; i < TYPE_COUNT; i++)
        if(strcmp(fields[1], types[i].name) == 0) td = types[i].descriptor;
    if(!td) fail("unknown type %s", fields[1]);
    if(!syntax_of(fields[2], &decode_syntax)) fail("unknown decode syntax %s", fields[2]);
    if(strcmp(fields[3], "none") != 0 && !syntax_of(fields[3], &encode_syntax))
        fail("unknown encode syntax %s", fields[3]);
    size = parse_hex(fields[4], wire);

    fputs("{\"id\":", stdout);
    json_string(fields[0]);
    fputs(",\"type\":", stdout);
    json_string(fields[1]);
    fputs(",\"decode\":{\"syntax\":", stdout);
    json_string(fields[2]);
    errno = 0;
    /* A NULL context selects asn1c's default stack bound (ASN__DEFAULT_STACK_MAX). */
    rval = asn_decode(NULL, decode_syntax, td, &value, wire, size);
    if(rval.code == RC_FAIL && errno == ENOENT) {
        /* asn1c has no decoder for this transfer syntax. */
        fputs(",\"status\":\"unsupported\",\"code\":\"RC_FAIL\"}", stdout);
    } else {
        static const char *codes[] = {"RC_OK", "RC_WMORE", "RC_FAIL"};
        const char *error = NULL;
        char detail[256] = "";
        size_t detail_size = sizeof(detail);
        if(rval.code == RC_OK && rval.consumed < size) error = "trailing";
        else if(rval.code == RC_WMORE) error = size ? "truncated" : "empty";
        else if(rval.code == RC_FAIL) error = "malformed";
        else if(asn_check_constraints(td, value, detail, &detail_size)) error = "constraint";
        printf(",\"status\":\"%s\",\"code\":\"%s\",\"consumed\":%lu", error ? "rejected" : "accepted",
               codes[rval.code], (unsigned long)rval.consumed);
        if(error) {
            fputs(",\"error\":", stdout);
            json_string(error);
            if(detail[0]) {
                fputs(",\"detail\":", stdout);
                json_string(detail);
            }
        } else {
            fputs(",\"value\":", stdout);
            json_value(td, value, 0);
        }
        putchar('}');
        if(!error && encode_syntax != ATS_INVALID) encode(td, value, fields[3], encode_syntax);
    }
    puts("}");
    fflush(stdout);
    ASN_STRUCT_FREE(*td, value);
}

int main(void) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    size_t i;
    printf("{\"adapter\":\"asn1c\",\"version\":");
    json_string(TESTLAB_ASN1C_VERSION);
    printf(",\"environment_version\":%d,\"schema\":", get_asn1c_environment_version());
    json_string(TESTLAB_SCHEMA);
    fputs(",\"schema_sha256\":", stdout);
    json_string(TESTLAB_SCHEMA_SHA256);
    fputs(",\"types\":[", stdout);
    for(i = 0; i < TYPE_COUNT; i++) {
        if(i) putchar(',');
        json_string(types[i].name);
    }
    puts("]}");
    fflush(stdout);
    while((length = getline(&line, &capacity, stdin)) != -1) {
        if(length > 0 && line[length - 1] == '\n') line[--length] = '\0';
        handle(line);
    }
    free(line);
    return ferror(stdin) ? 2 : 0;
}
