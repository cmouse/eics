bin_PROGRAMS = eics
eics_SOURCES = config.h eics.hh filesystem.cc policy.cc eics.hh entry.cc hash.cc logging.cc keys.cc getpass.c processor.cc misc.cc main.cc
eics_CXXFLAGS = $(BOOST_CPPFLAGS) $(openssl_CFLAGS)
eics_LDADD = $(BOOST_FILESYSTEM_LDFLAGS) $(BOOST_FILESYSTEM_LIBS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS) $(BOOST_PROGRAM_OPTIONS_LIBS) $(BOOST_SYSTEM_LDFLAGS) $(BOOST_SYSTEM_LIBS) $(BOOST_THREAD_LDFLAGS) $(BOOST_THREAD_LIBS) $(openssl_LIBS) 
