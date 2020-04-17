%global gtk2 1
%global pie 1
# Add option to build without GTK2 for older platforms with only GTK+.
# rpm -ba|--rebuild --define 'no_gtk2 1'
%{?no_gtk2:%global gtk2 0}

%global pam_ssh_agent_rel 5

%global sshd_uid    74

Name:          openssh
Version:       7.8p1
Release:       8
URL:           https://www.openssh.com/portable.html
License:       BSD
Summary:       An open source implementation of SSH protocol version 2

Source0:       https://ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
Source1:       https://ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
Source2:       sshd.pam
Source3:       DJM-GPG-KEY.gpg
Source4:       https://prdownloads.sourceforge.net/pamsshagentauth/pam_ssh_agent_auth/pam_ssh_agent_auth-0.10.3.tar.bz2
Source5:       pam_ssh_agent-rmheaders
Source6:       ssh-keycat.pam
Source7:       sshd.sysconfig
Source9:       sshd@.service
Source10:      sshd.socket
Source11:      sshd.service
Source12:      sshd-keygen@.service
Source13:      sshd-keygen
Source14:      sshd.tmpfiles
Source15:      sshd-keygen.target

Patch100:      openssh-6.7p1-coverity.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=735889
Patch104:      openssh-7.3p1-openssl-1.1.0.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=1171248
Patch200:      openssh-7.6p1-audit.patch
Patch201:      openssh-7.1p2-audit-race-condition.patch
Patch300:      pam_ssh_agent_auth-0.9.3-build.patch
Patch301:      pam_ssh_agent_auth-0.10.3-seteuid.patch
Patch302:      pam_ssh_agent_auth-0.9.2-visibility.patch
Patch305:      pam_ssh_agent_auth-0.9.3-agent_structure.patch
Patch306:      pam_ssh_agent_auth-0.10.2-compat.patch
Patch307:      pam_ssh_agent_auth-0.10.2-dereference.patch
Patch400:      openssh-7.8p1-role-mls.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=781634
Patch404:      openssh-6.6p1-privsep-selinux.patch
Patch501:      openssh-6.7p1-ldap.patch
Patch502:      openssh-6.6p1-keycat.patch
Patch601:      openssh-6.6p1-allow-ip-opts.patch
Patch604:      openssh-6.6p1-keyperm.patch
Patch606:      openssh-5.9p1-ipv6man.patch
Patch607:      openssh-5.8p2-sigpipe.patch
Patch609:      openssh-7.2p2-x11.patch
Patch700:      openssh-7.7p1-fips.patch
Patch702:      openssh-5.1p1-askpass-progress.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=198332
Patch703:      openssh-4.3p2-askpass-grab-info.patch
#patch from redhat 
Patch707:      openssh-7.7p1.patch
Patch709:      openssh-6.2p1-vendor.patch
Patch711:      openssh-7.8p1-UsePAM-warning.patch
Patch712:      openssh-6.3p1-ctr-evp-fast.patch
Patch713:      openssh-6.6p1-ctr-cavstest.patch
Patch714:      openssh-6.7p1-kdf-cavs.patch
Patch800:      openssh-7.8p1-gsskex.patch
Patch801:      openssh-6.6p1-force_krb.patch
Patch802:      openssh-6.6p1-GSSAPIEnablek5users.patch
# from https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=765655
Patch803:      openssh-7.1p1-gssapi-documentation.patch
Patch804:      openssh-7.7p1-gssapi-new-unique.patch
Patch805:      openssh-7.2p2-k5login_directory.patch
Patch807:      openssh-7.5p1-gssapi-kex-with-ec.patch
Patch900:      openssh-6.1p1-gssapi-canohost.patch
Patch901:      openssh-6.6p1-kuserok.patch
Patch906:      openssh-6.4p1-fromto-remote.patch
Patch916:      openssh-6.6.1p1-selinux-contexts.patch
Patch918:      openssh-6.6.1p1-log-in-chroot.patch
Patch919:      openssh-6.6.1p1-scp-non-existing-directory.patch
Patch920:      openssh-7.8p1-ip-port-config-parser.patch
Patch922:      openssh-6.8p1-sshdT-output.patch
Patch926:      openssh-6.7p1-sftp-force-permission.patch
Patch929:      openssh-6.9p1-permit-root-login.patch
Patch932:      openssh-7.0p1-gssKexAlgorithms.patch
Patch939:      openssh-7.2p2-s390-closefrom.patch
Patch944:      openssh-7.3p1-x11-max-displays.patch
Patch948:      openssh-7.4p1-systemd.patch
Patch949:      openssh-7.6p1-cleanup-selinux.patch
Patch950:      openssh-7.5p1-sandbox.patch
Patch951:      openssh-7.6p1-pkcs11-uri.patch
Patch952:      openssh-7.6p1-pkcs11-ecdsa.patch
Patch953:      openssh-7.8p1-scp-ipv6.patch

Patch6000:     Initial-len-for-the-fmt-NULL-case.patch
Patch6001:     upstream-fix-build-with-DEBUG_PK-enabled.patch
Patch6002:     upstream-fix-misplaced-parenthesis-inside-if-clause..patch
Patch6003:     delete-the-correct-thing-kexfuzz-binary.patch
Patch6004:     upstream-When-choosing-a-prime-from-the-moduli-file-.patch
Patch6005:     upstream-fix-ssh-Q-sig-to-show-correct-signature-alg.patch
Patch6006:     in-pick_salt-avoid-dereference-of-NULL-passwords.patch
Patch6007:     check-for-NULL-return-from-shadow_pw.patch
Patch6008:     check-pw_passwd-NULL-here-too.patch
Patch6009:     upstream-typo-in-plain-RSA-algorithm-counterpart-nam.patch
Patch6010:     upstream-correct-local-variable-name-from-yawang-AT-.patch
Patch6011:     upstream-typo-in-error-message-caught-by-Debian-lint.patch
Patch6012:     upstream-fix-bug-in-HostbasedAcceptedKeyTypes-and.patch
Patch6013:     upstream-fix-bug-in-client-that-was-keeping-a-redund.patch
Patch6014:     upstream-disallow-empty-incoming-filename-or-ones-th.patch
Patch6015:     upstream-make-grandparent-parent-child-sshbuf-chains.patch
Patch6016:     Move-RANDOM_SEED_SIZE-outside-ifdef.patch
Patch6017:     upstream-don-t-truncate-user-or-host-name-in-user-ho.patch
Patch6018:     upstream-don-t-attempt-to-connect-to-empty-SSH_AUTH_.patch
Patch6019:     upstream-only-consider-the-ext-info-c-extension-duri.patch
Patch6020:     upstream-fix-memory-leak-of-ciphercontext-when-rekey.patch
Patch6021:     upstream-Fix-BN_is_prime_-calls-in-SSH-the-API-retur.patch
Patch6022:     upstream-Always-initialize-2nd-arg-to-hpdelim2.-It-p.patch
Patch6023:     Cygwin-Change-service-name-to-cygsshd.patch
Patch6024:     openssh-fix-typo-that-prevented-detection-of-Linux-V.patch

Patch6025:     CVE-2019-6109-1.patch
Patch6026:     CVE-2019-6109-2.patch
Patch6027:     CVE-2019-6111-1.patch
Patch6028:     CVE-2019-6111-2.patch
Patch6029:     CVE-2019-16905.patch
Patch6030:     upstream-fix-sshd-T-without-C.patch

Patch9004:     bugfix-sftp-when-parse_user_host_path-empty-path-should-be-allowed.patch
Patch9005:     bugfix-openssh-6.6p1-log-usepam-no.patch
Patch9006:     bugfix-openssh-add-option-check-username-splash.patch
Patch9007:     feature-openssh-7.4-hima-sftpserver-oom-and-fix.patch
Patch9008:     bugfix-supply-callback-to-PEM-read-bio-PrivateKey.patch
Patch9009:     bugfix-openssh-fix-sftpserver.patch
Patch9010:     bugfix-CVE-2018-15919.patch

Requires:      /sbin/nologin libselinux >= 2.3-5 audit-libs >= 1.0.8
Requires:      fipscheck-lib >= 1.3.0 
Requires(pre): /usr/sbin/useradd
Requires(pre): shadow-utils
Requires:      pam >= 1.0.1-3
Requires:      fipscheck-lib >= 1.3.0
Requires:      crypto-policies >= 20180306-1

Obsoletes:     openssh-clients-fips openssh-server-fips openssh-server-sysvinit openssh-cavs openssh-askpass-gnome
Obsoletes:     openssh-clients openssh-server openssh-ldap openssh-keycat openssh-askpass 
Provides:      openssh-clients openssh-server openssh-ldap openssh-keycat openssh-askpass openssh-cavs openssh-askpass-gnome

BuildRequires: gtk2-devel libX11-devel openldap-devel autoconf automake perl-interpreter perl-generators
BuildRequires: zlib-devel audit-libs-devel >= 2.0.5 util-linux groff pam-devel fipscheck-devel >= 1.3.0
BuildRequires: openssl-devel >= 0.9.8j perl-podlators systemd-devel gcc p11-kit-devel krb5-devel
BuildRequires: libedit-devel ncurses-devel libselinux-devel >= 2.3-5 audit-libs >= 1.0.8 xauth gnupg2

%{?systemd_requires}

Recommends:    p11-kit

%description
OpenSSH is the premier connectivity tool for remote login with the SSH protocol. \
It encrypts all traffic to eliminate eavesdropping, connection hijacking, and \
other attacks. In addition, OpenSSH provides a large suite of secure tunneling \
capabilities, several authentication methods, and sophisticated configuration options.

%package -n pam_ssh_agent_auth
Summary: PAM module for the use of authentication with ssh-agent
Version: 0.10.3
Release: %{pam_ssh_agent_rel}.4
License: BSD

%description -n pam_ssh_agent_auth
Provides PAM module for the use of authentication with ssh-agent. Through the use of the\
forwarding of ssh-agent connection it also allows to authenticate with remote ssh-agent \
instance. The module is most useful for su and sudo service stacks.

%package_help

%prep
gpgv2 --quiet --keyring %{SOURCE3} %{SOURCE1} %{SOURCE0}
%setup -q -a 4

pushd pam_ssh_agent_auth-0.10.3
%patch300 -p2 -b .psaa-build
%patch301 -p2 -b .psaa-seteuid
%patch302 -p2 -b .psaa-visibility
%patch306 -p2 -b .psaa-compat
%patch305 -p2 -b .psaa-agent
%patch307 -p2 -b .psaa-deref
# Remove duplicate headers and library files
rm -f $(cat %{SOURCE5})
popd

%patch400 -p1 -b .role-mls
%patch404 -p1 -b .privsep-selinux
%patch501 -p1 -b .ldap
%patch502 -p1 -b .keycat
%patch601 -p1 -b .ip-opts
%patch604 -p1 -b .keyperm
%patch606 -p1 -b .ipv6man
%patch607 -p1 -b .sigpipe
%patch609 -p1 -b .x11
%patch702 -p1 -b .progress
%patch703 -p1 -b .grab-info
%patch707 -p1 
%patch709 -p1 -b .vendor
%patch711 -p1 -b .log-usepam-no
%patch712 -p1 -b .evp-ctr
%patch713 -p1 -b .ctr-cavs
%patch714 -p1 -b .kdf-cavs
%patch800 -p1 -b .gsskex
%patch801 -p1 -b .force_krb
%patch803 -p1 -b .gss-docs
%patch804 -p1 -b .ccache_name
%patch805 -p1 -b .k5login
%patch900 -p1 -b .canohost
%patch901 -p1 -b .kuserok
%patch906 -p1 -b .fromto-remote
%patch916 -p1 -b .contexts
%patch918 -p1 -b .log-in-chroot
%patch919 -p1 -b .scp
%patch920 -p1 -b .config
%patch802 -p1 -b .GSSAPIEnablek5users
%patch922 -p1 -b .sshdt
%patch926 -p1 -b .sftp-force-mode
%patch929 -p1 -b .root-login
%patch932 -p1 -b .gsskexalg
%patch939 -p1 -b .s390-dev
%patch944 -p1 -b .x11max
%patch948 -p1 -b .systemd
%patch807 -p1 -b .gsskex-ec
%patch949 -p1 -b .refactor
%patch950 -p1 -b .sandbox
%patch951 -p1 -b .pkcs11-uri
%patch952 -p1 -b .pkcs11-ecdsa
%patch953 -p1 -b .scp-ipv6
%patch200 -p1 -b .audit
%patch201 -p1 -b .audit-race
%patch700 -p1 -b .fips
%patch100 -p1 -b .coverity
%patch104 -p1 -b .openssl

%patch6000 -p1
%patch6001 -p1
%patch6002 -p1
%patch6003 -p1
%patch6004 -p1
%patch6005 -p1
%patch6006 -p1
%patch6007 -p1
%patch6008 -p1
%patch6009 -p1
%patch6010 -p1
%patch6011 -p1
%patch6012 -p1
%patch6013 -p1
%patch6014 -p1
%patch6015 -p1
%patch6016 -p1
%patch6017 -p1
%patch6018 -p1
%patch6019 -p1
%patch6020 -p1
%patch6021 -p1
%patch6022 -p1
%patch6023 -p1
%patch6024 -p1
%patch6025 -p1
%patch6026 -p1
%patch6027 -p1
%patch6028 -p1
%patch6029 -p1

%patch9004 -p1
%patch9005 -p1
%patch9006 -p1
%patch9007 -p1
%patch9008 -p1
%patch9009 -p1

%patch6030 -p1
%patch9010 -p1

autoreconf
pushd pam_ssh_agent_auth-0.10.3
autoreconf
popd

%build
CFLAGS="$RPM_OPT_FLAGS -fvisibility=hidden"; export CFLAGS

%ifarch s390 s390x sparc sparcv9 sparc64
CFLAGS="$CFLAGS -fPIC"
%else
CFLAGS="$CFLAGS -fpic"
%endif
SAVE_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -pie -z relro -z now"

export CFLAGS
export LDFLAGS

if test -r /etc/profile.d/krb5-devel.sh ; then
	source /etc/profile.d/krb5-devel.sh
fi
krb5_prefix=`krb5-config --prefix`
if test "$krb5_prefix" != "%{_prefix}" ; then
	CPPFLAGS="$CPPFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"
	LDFLAGS="$LDFLAGS -L${krb5_prefix}/%{_lib}"; export LDFLAGS
else
	krb5_prefix=
	CPPFLAGS="-I%{_includedir}/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I%{_includedir}/gssapi"
fi

%configure \
	--sysconfdir=%{_sysconfdir}/ssh --libexecdir=%{_libexecdir}/openssh \
	--datadir=%{_datadir}/openssh --with-default-path=/usr/local/bin:/usr/bin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_var}/empty/sshd -disable-strip \
	--enable-vendor-patchlevel="FC-7.8p1-3" \
	--without-zlib-version-check --with-ssl-engine --with-ipaddr-display \
	--with-pie=no --without-hardening --with-systemd --with-default-pkcs11-provider=yes \
	--with-ldap --with-pam --with-selinux --with-audit=linux --with-sandbox=seccomp_filter \
	--with-kerberos5${krb5_prefix:+=${krb5_prefix}} --with-libedit

make
gtk2=yes

pushd contrib
if [ $gtk2 = yes ] ; then
	CFLAGS="$CFLAGS %{?__global_ldflags}" \
	    make gnome-ssh-askpass2
	mv gnome-ssh-askpass2 gnome-ssh-askpass
else
	CFLAGS="$CFLAGS %{?__global_ldflags}"
	    make gnome-ssh-askpass1
	mv gnome-ssh-askpass1 gnome-ssh-askpass
fi
popd

pushd pam_ssh_agent_auth-0.10.3
LDFLAGS="$SAVE_LDFLAGS"
%configure --with-selinux --libexecdir=/%{_libdir}/security --with-mantype=man
make
popd

%global __spec_install_post \
    %%{?__debug_package:%%{__debug_install_post}} %%{__arch_install_post} %%{__os_install_post} \
    fipshmac -d $RPM_BUILD_ROOT%{_libdir}/fipscheck $RPM_BUILD_ROOT%{_bindir}/ssh $RPM_BUILD_ROOT%{_sbindir}/sshd \
%{nil}

%check
#to run tests use "--with check"
%if %{?_with_check:1}%{!?_with_check:0}
make tests
%endif

%install
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/ssh
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/ssh/ssh_config.d
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/openssh
mkdir -p -m755 $RPM_BUILD_ROOT%{_var}/empty/sshd

%make_install

rm -f $RPM_BUILD_ROOT%{_sysconfdir}/ssh/ldap.conf

mkdir -p $RPM_BUILD_ROOT/etc/pam.d/
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig/
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}/openssh
mkdir -p $RPM_BUILD_ROOT%{_libdir}/fipscheck
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/pam.d/sshd
install -m644 %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/ssh-keycat
install -m644 %{SOURCE7} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install -m644 ssh_config_redhat $RPM_BUILD_ROOT/etc/ssh/ssh_config.d/05-redhat.conf
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -m644 %{SOURCE9} $RPM_BUILD_ROOT/%{_unitdir}/sshd@.service
install -m644 %{SOURCE10} $RPM_BUILD_ROOT/%{_unitdir}/sshd.socket
install -m644 %{SOURCE11} $RPM_BUILD_ROOT/%{_unitdir}/sshd.service
install -m644 %{SOURCE12} $RPM_BUILD_ROOT/%{_unitdir}/sshd-keygen@.service
install -m644 %{SOURCE15} $RPM_BUILD_ROOT/%{_unitdir}/sshd-keygen.target
install -m744 %{SOURCE13} $RPM_BUILD_ROOT/%{_libexecdir}/openssh/sshd-keygen
install -m755 contrib/ssh-copy-id $RPM_BUILD_ROOT%{_bindir}/
install contrib/ssh-copy-id.1 $RPM_BUILD_ROOT%{_mandir}/man1/
install -m644 -D %{SOURCE14} $RPM_BUILD_ROOT%{_tmpfilesdir}/%{name}.conf
install contrib/gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/gnome-ssh-askpass

ln -s gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/ssh-askpass
install -m 755 -d $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
install -m 755 contrib/redhat/gnome-ssh-askpass.csh $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
install -m 755 contrib/redhat/gnome-ssh-askpass.sh $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

pushd pam_ssh_agent_auth-0.10.3
make install DESTDIR=$RPM_BUILD_ROOT
popd

%pre
getent group ssh_keys >/dev/null || groupadd -r ssh_keys || :
getent group sshd >/dev/null || groupadd -g %{sshd_uid} -r sshd || :
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd \
  -s /sbin/nologin -r -d /var/empty/sshd sshd 2> /dev/null || :

%post 
%systemd_post sshd.service sshd.socket

%preun 
%systemd_preun sshd.service sshd.socket

%postun 
%systemd_postun_with_restart sshd.service

%files
%defattr(-,root,root)
%doc CREDITS INSTALL README.platform
%license LICENCE
%dir %attr(0711,root,root) %{_var}/empty/sshd
%attr(0644,root,root) %{_tmpfilesdir}/openssh.conf
%attr(0644,root,root) %config(noreplace) /etc/pam.d/ssh*        
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/sshd
%attr(0755,root,root) %dir %{_sysconfdir}/ssh
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ssh/moduli
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ssh/ssh_config
%dir %attr(0755,root,root) %{_sysconfdir}/ssh/ssh_config.d/
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ssh/ssh_config.d/05-redhat.conf
%attr(0644,root,root) %{_sysconfdir}/profile.d/gnome-ssh-askpass.*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/sshd_config
%attr(0755,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %{_bindir}/ssh*
%attr(0755,root,root) %{_bindir}/scp
%attr(0755,root,root) %{_bindir}/sftp
%attr(0644,root,root) %{_libdir}/fipscheck/ssh*.hmac
%attr(0755,root,root) %dir %{_libexecdir}/openssh
%attr(2555,root,ssh_keys) %{_libexecdir}/openssh/ssh-keysign
%attr(0755,root,root) %{_libexecdir}/openssh/ctr-cavstest
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-cavs*
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-pkcs11-helper
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-ldap-*
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-keycat
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-askpass
%attr(0755,root,root) %{_libexecdir}/openssh/sftp-server
%attr(0755,root,root) %{_libexecdir}/openssh/sshd-keygen
%attr(0755,root,root) %{_libexecdir}/openssh/gnome-ssh-askpass
%attr(0644,root,root) %{_unitdir}/sshd*

%files -n pam_ssh_agent_auth
%defattr(-,root,root)
%license pam_ssh_agent_auth-0.10.3/OPENSSH_LICENSE
%attr(0755,root,root) %{_libdir}/security/pam_ssh_agent_auth.so

%files help
%defattr(-,root,root)
%doc ChangeLog OVERVIEW PROTOCOL* README README.privsep README.tun README.dns TODO openssh-lpk-openldap.schema
%doc openssh-lpk-sun.schema ldap.conf openssh-lpk-openldap.ldif openssh-lpk-sun.ldif HOWTO.ssh-keycat HOWTO.ldap-keys
%attr(0644,root,root) %{_mandir}/man1/scp.1*
%attr(0644,root,root) %{_mandir}/man1/ssh*.1*
%attr(0644,root,root) %{_mandir}/man1/sftp.1*
%attr(0644,root,root) %{_mandir}/man5/ssh*.5*
%attr(0644,root,root) %{_mandir}/man5/moduli.5*
%attr(0644,root,root) %{_mandir}/man8/ssh*.8*
%attr(0644,root,root) %{_mandir}/man8/pam_ssh_agent_auth.8*
%attr(0644,root,root) %{_mandir}/man8/sftp-server.8*

%changelog
* Wed Mar 18 2020 songnannan <songnannan2@huawei.com> - 7.8P1-8
- bugfix CVE-2018-15919

* Tue Jan 21 2020 openEuler Buildteam <buildteam@openeuler.org> - 7.8P1-7
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:add the patch for bugfix

* Mon Dec 23 2019 openEuler Buildteam <buildteam@openeuler.org> - 7.8P1-6
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:delete the patch

* Sat Dec 21 2019 openEuler Buildteam <buildteam@openeuler.org> - 7.8P1-5
- Type:cves
- ID:NA
- SUG:restart
- DESC:fix cves

* Fri Sep 20 2019 openEuler Buildteam <buildteam@openeuler.org> - 7.8p1-4
- Package init
