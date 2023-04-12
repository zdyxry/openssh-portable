FROM openeuler/openeuler:20.03

RUN rm -f /etc/yum.repos.d/*.repo

ADD ./build/openEuler.repo /etc/yum.repos.d/openEuler.repo

RUN dnf -y install rpm-build dnf-plugins-core \
    && mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

COPY ./* /root/rpmbuild/SOURCES/

RUN dnf -y builddep /root/rpmbuild/SOURCES/openssh.spec \
    && rpmbuild -ba /root/rpmbuild/SOURCES/openssh.spec --nocheck

