/* Translation unit bindgen is pointed at.
 *
 * Only the epan surface the dissector actually uses is pulled in. Including <epan/packet.h>
 * alone would still transitively reach most of libwireshark, but listing the headers keeps
 * the intent readable and makes an accidental new dependency visible in the diff.
 *
 * Everything used from here is a real exported symbol of libwireshark (`WS_DLL_PUBLIC`), so no
 * C shims are needed — including for the `col_*` column helpers, which are functions rather
 * than the macros they look like at the call site.
 */

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/column-utils.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/plugins.h>
