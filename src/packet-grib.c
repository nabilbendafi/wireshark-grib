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

/* The handle for the dynamic dissector */
static dissector_handle_t grib_handle = NULL;
static gboolean grib_handle_inited = FALSE;

/* Global preferences */
static range_t *global_grib_tcp_port_range;
static range_t *grib_tcp_port_range;

/* Initialize the protocol and registered fields */
static int proto_grib = -1;

/* Forward declarations we need below */
void proto_register_grib(void);
void proto_reg_handoff_grib(void);
static void grib_init_protocol(void);

/* Register the protocol with Wireshark */
void proto_register_grib(void) {

    module_t *grib_module;

    /* Register the protocol name and description */
    proto_grib = proto_register_protocol("GRIB", "GRIB", "grib");

    grib_module = prefs_register_protocol(proto_grib, proto_reg_handoff_grib);

    /* Register protocol init routine */
    register_init_routine(grib_init_protocol);

} /* proto_register_grib */

static void register_grib_port(guint32 port) {
    dissector_add("tcp.port", port, grib_handle);
}

static void unregister_grib_port(guint32 port) {
    dissector_delete("tcp.port", port, grib_handle);
}

static void grib_init_protocol(void) {
    //if (grib_handle_inited) // add port handlers (settings should be loaded by now)
        proto_reg_handoff_grib();
}

/* The registration hand-off routine */
void proto_reg_handoff_grib(void) {
    ;
} /* proto_reg_handoff_grib */
