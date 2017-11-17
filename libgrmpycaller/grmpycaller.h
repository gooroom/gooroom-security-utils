/* 
 * Copyright (C) 2015-2017 Gooroom <gooroom@gooroom.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef PYCALLER_H
#define PYCALLER_H

#define VERIFY_SUCCESS                  0
#define FILE_OPEN_ERROR                 -1
#define READ_PUBKEY_FROM_CERT_ERROR     -2
#define DIGEST_VERIFY_INIT_ERROR        -3
#define DIGEST_VERIFY_UPDATE_ERROR      -4
#define DIGEST_VERIFY_FINAL_ERROR       -5

#define PYTHONPATH  "PYTHONPATH=/usr/lib/gooroom-security-utils/pycaller/"
#define MODULE_NAME "pycaller"
#define FUNC_NAME "do_task"

#ifdef __cplusplus
extern "C" {
int verify_signature(const char *file_path);
char* do_task(const char *task);
}
#else
int verify_signature(const char *file_path);
char* do_task(const char *task);
#endif //__cplusplus

#endif //PYCALLER_H
