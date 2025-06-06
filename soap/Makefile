#
# soap/Makefile.in - extending Makefile.in for SOAP web services
#
# This file is included from main Makefile, and contains various
# targets and definitions to build the SOAP related object files
# and libraries.
#
# This file is currently maintained manually. There is currently
# no generation out of automake. This will change as soon as we
# switch to our new autoconf/configure build process.
#
# Stipe Tolj <stolj at kannel.org>
#
# NOTE: At this time we CAN NOT build several gSOAP plugin
# implementations using this build framework. The problem
# arises from namespace clashes and the way gSOAP deals with
# the individual soap_serve() functions internally while linking,
# especially if WS-Security is used. 
#
# If you need an additional gSOAP based implementation, then
# change the build process to build ONLY ONE.
# 

SOAPCPP = 
WSDL2H = 
GSOAP_SHARE = 
GSOAP_IMPORT = $(GSOAP_SHARE)/import
GSOAP_PLUGIN = $(GSOAP_SHARE)/plugin

LIBS=-lgsoapssl -lgsoap -lrt -lresolv -lnsl -lm  -lpthread -lxml2 -lm -pthread -lz -llzma -pthread -lpthread -licuuc -licudata -lpthread -lm -L/usr/lib -lhiredis 
CFLAGS=-D_REENTRANT=1 -I. -Igw -g -O2 -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_LARGE_FILES= -DBROKEN_PTHREADS=1 -I/usr/include/libxml2 -I/usr/include/hiredis -I$(GSOAP_IMPORT) -I$(GSOAP_PLUGIN) -DWITH_OPENSSL \
	-Isoap/service/parlayx

#
# gSOAP plugin library, i.e. required for WS-Security
#
gsoap_plugin_srcs = $(GSOAP_PLUGIN)/wsseapi.c \
	$(GSOAP_PLUGIN)/smdevp.c \
	$(GSOAP_PLUGIN)/mecevp.c

soap_plugin_srcs = soap/plugin/wsseapi.c \
	soap/plugin/smdevp.c \
	soap/plugin/mecevp.c
	
soap_plugin_objs = $(soap_plugin_srcs:.c=.o)

soap/plugin/wsseapi.c: $(GSOAP_PLUGIN)/wsseapi.c
	ln -sf $(GSOAP_PLUGIN)/wsseapi.c soap/plugin/wsseapi.c

soap/plugin/smdevp.c: $(GSOAP_PLUGIN)/smdevp.c
	ln -sf $(GSOAP_PLUGIN)/smdevp.c soap/plugin/smdevp.c

soap/plugin/mecevp.c: $(GSOAP_PLUGIN)/mecevp.c
	ln -sf $(GSOAP_PLUGIN)/mecevp.c soap/plugin/mecevp.c

libsoap_plugin.a: $(soap_plugin_objs)
	ar rc libsoap_plugin.a $(soap_plugin_objs)
	$(RANLIB) libsoap_plugin.a

#
# Service implementation: Parlay X v2.1
#
soap_parlayx_wsdls = soap/service/parlayx/wsdl/parlayx_sms_send_service_2_1.wsdl \
	soap/service/parlayx/wsdl/parlayx_sms_notification_service_2_1.wsdl \
	soap/service/parlayx/wsdl/parlayx_sms_receive_service_2_1.wsdl 
soap_parlayx_cppsrc = soap/service/parlayx/parlayx_sms_send_service_2_1.h
soap_parlayx_cppwrap =  soap/service/parlayx/parlayx_sms_send_service_2_1_wrapper.h
soap_parlayx_cpphdr = soap/service/parlayx/soapH.h
soap_parlayx_srcs = $(wildcard soap/service/parlayx/*.c)
soap_parlayx_objs = $(soap_parlayx_srcs:.c=.o)

$(soap_parlayx_cppsrc): $(soap_parlayx_wsdls)
	$(WSDL2H) -c -W -npx -t soap/service/parlayx/typemap.dat -o $(soap_parlayx_cppsrc) -I soap/service/parlayx/wsdl $(soap_parlayx_wsdls)
	sed -i -e '/^\/\/gsoapopt/d' $(soap_parlayx_cppsrc)
	
$(soap_parlayx_cpphdr): $(soap_parlayx_cppwrap) $(soap_parlayx_cppsrc)
	$(SOAPCPP) -d `dirname $(soap_parlayx_cpphdr)` -I $(GSOAP_IMPORT) -I soap/service/parlayx -cLxw $(soap_parlayx_cppwrap)
	
libsoap_parlayx.a: $(soap_parlayx_cpphdr) $(soap_parlayx_plugin_srcs) $(soap_parlayx_objs)
	ar rc libsoap_parlayx.a $(soap_parlayx_objs)
	$(RANLIB) libsoap_parlayx.a

#
# Define all soapcpp2 header inputs
# Add $(soap_SERVICE_cpphdr) for new implementation.
#
gsoap_cpp_hdrs = $(soap_parlayx_cpphdr)

# Add libsoap_SERVICE.a for new implementation.
libs = libgw.a libwmlscript.a libwap.a libgwlib.a libsoap_plugin.a \
	libsoap_parlayx.a

# Add soap/service/SERVICE for new implementation.
srcdirs = gw gw/smsc gwlib test utils wmlscript checks wap radius soap/service/plugin \
	soap/service/parlayx
	
soap_depend = $(gsoap_cpp_hdrs)

soap_clean:
	find soap -name "*.o" -o -name "*.i" -o -name "*.c" \
		-o -name "soap*.h" -o -name "*.nsmap" | xargs rm -f
	find . -name "libsoap_*.a" | xargs rm -f
