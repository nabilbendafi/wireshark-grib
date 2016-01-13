/* packet-grib.c
 * Routines for GRIB dissection
 *
 * Copyright (c) 2016 Nabil BENDAFI
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/garrayfix.h>

#include <grib_api_version.h>
#include <grib_api.h>
#include <grib_api_internal.h>
#include "grib_dumper_class.h"

#define MAX_STRING_LEN  512

/* The handle for the dynamic dissector */
static dissector_handle_t grib_tcp_handle = NULL;
static gboolean grib_handle_inited = FALSE;

/* Global preferences */
static range_t *global_grib_tcp_port_range;
static range_t *grib_tcp_port_range;

/* Initialize the protocol and registered fields */
static int proto_grib = -1;
static gint ett_grib = -1;
static gint ett_sections[MAX_NUM_SECTIONS];
static hf_register_info* hf = NULL;
static int hf_grib_identifier = -1;
static int hf_grib_end_section = -1;

/* Forward declarations we need below */
void proto_register_grib(void);
void proto_reg_handoff_grib(void);
static void grib_init_protocol(void);

grib_context* grib_api_context = NULL;
grib_handle* grib_api_handle = NULL;

/* Register the protocol with Wireshark */
void proto_register_grib(void) {

    int i, j;
    module_t *grib_module;

    /* Register the protocol name and description */
    proto_grib = proto_register_protocol("GRIB", "GRIB", "grib");

    /* Register the protocol preferences */
    grib_module = prefs_register_protocol(proto_grib, proto_reg_handoff_grib);

    prefs_register_range_preference(grib_module, "tcp.grib_ports",
                                    "GRIB listener TCP Ports",
                                    "Set the TCP ports for GRIB",
                                    &global_grib_tcp_port_range, MAX_TCP_PORT);

    /* Register protocol init routine */
    register_init_routine(grib_init_protocol);

    static hf_register_info hf[] = {
        { &hf_grib_identifier,
            { "Identifier", "grib.identifier",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_grib_end_section,
            { "End Section", "grib.end_section",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[1 + MAX_NUM_SECTIONS];

    ett[0] = &ett_grib;

    for (i=0, j=1; i<MAX_NUM_SECTIONS; i++, j++) {
        ett[j] = &ett_sections[i];
        ett_sections[i] = -1;
    }

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_grib, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

} /* proto_register_grib */

static void register_grib_port(guint32 port) {
    if (port != 0)
        dissector_add_uint("tcp.port", port, grib_tcp_handle);
}

static void unregister_grib_port(guint32 port) {
    if (port != 0)
        dissector_delete_uint("tcp.port", port, grib_tcp_handle);
}

static void grib_init_protocol(void) {
    int e = 0;
    FILE *f = fopen("/tmp/GRIB2.tmpl","r");

    grib_api_context = grib_context_get_default(); 
    grib_api_handle = grib_handle_new_from_file(NULL, f, &e);
} /* grib_init_protocol */

static guint get_grib_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset) {
    return 179;
}

/* The GRIB dissector code */
static int dissect_grib_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    long length = 0;
    proto_item *grib_item = NULL, *grib_protocol_length = NULL;
    proto_tree *grib_tree;
    proto_tree *grib_sections[MAX_NUM_SECTIONS];

    /* Add the protocol to the column */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "GRIB");
    /* Clear out stuff in the info column */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        int current_section = 0;

        /* Get the length field */
        grib_get_long(grib_api_handle, "totalLength", &length);

        /* Add the length to the info column */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Length=%d ", (int)length);

        /* Add the GRIB subtree */
        grib_item = proto_tree_add_item(tree, proto_grib, tvb, 0, -1, FALSE);
        grib_tree = proto_item_add_subtree(grib_item, ett_grib);

        /* Add the section subtrees */
        int i;
        proto_item *grib_section = NULL;
        for (i=0; i<MAX_NUM_SECTIONS; i++) {
            char key[15];
            long section_len = 0;
            long section_offset = 0;

            sprintf(key, "section%dLength", i);
            grib_get_long(grib_api_handle, key, &section_len);

            sprintf(key, "offsetSection%d", i);
            grib_get_long(grib_api_handle, key, &section_offset);

            if (section_len != 0) {
                grib_section = proto_tree_add_text(grib_tree, tvb, section_offset, section_len,
                                                   "Section %d", i);
                grib_sections[i] = proto_item_add_subtree(grib_section, ett_sections[i]);
            }
        }

        grib_keys_iterator* iterator = grib_keys_iterator_new(grib_api_handle,
                                                              GRIB_KEYS_ITERATOR_ALL_KEYS,
                                                              NULL);

        int type = 0;
        size_t len = 0;
        long offset = 0;

        double dvalue = 0;
        long lvalue = 0;
        char value[MAX_STRING_LEN];
        size_t value_len;

        int dump_flags = GRIB_DUMP_FLAG_CODED    |
                         GRIB_DUMP_FLAG_OCTECT   |
                         GRIB_DUMP_FLAG_VALUES   |
                         GRIB_DUMP_FLAG_READ_ONLY;

        while (grib_keys_iterator_next(iterator)) {

            dvalue = 0;
            lvalue = 0;
            value_len = 0;
            len = 0;

            grib_accessor* accessor = grib_keys_iterator_get_accessor(iterator);

            if (accessor->length == 0)
                continue;

            grib_get_native_type(grib_api_handle, accessor->name, &type);
            grib_get_size(grib_api_handle, accessor->name, &len);
            grib_get_length(grib_api_handle, accessor->name, &value_len);
            grib_get_offset(grib_api_handle, accessor->name, &offset);

            /* Dynamic hf_register_info item */
            gchar* abbrev = g_strconcat("grib.", accessor->name, NULL);

            /* Update section number */
            if (!strncmp(accessor->name, "section", 7)) {
                int section_num;
                sscanf(accessor->name, "section%dLength", &section_num);
                current_section = section_num;
            }

            if (!strncmp(accessor->name, "7777", 4))
                current_section = 8;

            switch (type) {
                case GRIB_TYPE_SECTION:
                    break;
                case GRIB_TYPE_STRING:
                    grib_get_string(grib_api_handle, accessor->name, value, &value_len);
                    proto_tree_add_string(grib_sections[current_section], hf_grib_identifier, tvb,
                                          accessor->offset, value_len, value);
                    break;
                case GRIB_TYPE_DOUBLE:
                    grib_get_double(grib_api_handle, accessor->name, &dvalue);
                    break;
                case GRIB_TYPE_LONG:
                    grib_get_long(grib_api_handle, accessor->name, &lvalue);
                    break;
                case GRIB_TYPE_BYTES:
                    grib_get_string(grib_api_handle, accessor->name, value, &value_len);
                    break;
                case GRIB_TYPE_LABEL:
                    break;
                defaulf:
                    break;
            }

            offset += accessor->offset;
        }

        /* Clean */
        grib_keys_iterator_delete(iterator);
    }

    return length;
} /* dissect_grib_message */

void dissect_grib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 3, get_grib_message_len, dissect_grib_message);
} /* dissect_grib */

void proto_reg_handoff_grib(void) {

    static gboolean grib_prefs_initialized = FALSE;

    if (!grib_prefs_initialized) {
        grib_tcp_handle = create_dissector_handle(dissect_grib, proto_grib);
        grib_prefs_initialized = TRUE;
    } else {
        if (grib_tcp_port_range != NULL)
            range_foreach(grib_tcp_port_range, unregister_grib_port);
    }

    g_free(grib_tcp_port_range);
    grib_tcp_port_range = range_copy(global_grib_tcp_port_range);
    range_foreach(grib_tcp_port_range, register_grib_port);
} /* proto_reg_handoff_grib */
