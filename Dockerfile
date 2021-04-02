FROM andrewlukoshko/cloudlinux-8-shim

ENV SHIM_VERSION 15.4-4.el8.cloudlinux

RUN wget https://github.com/cloudlinux/shim-review/raw/master/shim-unsigned-x64-$SHIM_VERSION.src.rpm
RUN rpm -ivh shim-unsigned-x64-$SHIM_VERSION.src.rpm
RUN sed -i "s/linux32 -B/linux32/" /root/rpmbuild/SPECS/shim-unsigned-x64.spec
RUN rpmbuild -bb /root/rpmbuild/SPECS/shim-unsigned-x64.spec
COPY shimia32.efi /
COPY shimx64.efi /
RUN rpm2cpio /root/rpmbuild/RPMS/x86_64/shim-unsigned-ia32-$SHIM_VERSION.x86_64.rpm | cpio -idmv
RUN rpm2cpio /root/rpmbuild/RPMS/x86_64/shim-unsigned-x64-$SHIM_VERSION.x86_64.rpm | cpio -idmv
RUN ls -l /*.efi ./usr/share/shim/$SHIM_VERSION/*/shim*.efi
RUN hexdump -Cv ./usr/share/shim/$SHIM_VERSION/x64/shimx64.efi > built-x64.hex
RUN hexdump -Cv ./usr/share/shim/$SHIM_VERSION/ia32/shimia32.efi > built-x32.hex
RUN hexdump -Cv /shimia32.efi > orig-x32.hex
RUN hexdump -Cv /shimx64.efi > orig-x64.hex
RUN objdump -h /usr/share/shim/$SHIM_VERSION/x64/shimx64.efi
RUN objdump -h /usr/share/shim/$SHIM_VERSION/ia32/shimia32.efi
#RUN diff -u orig-x32.hex built-x32.hex
#RUN diff -u orig-x64.hex built-x64.hex
RUN pesign -h -P -i /usr/share/shim/$SHIM_VERSION/x64/shimx64.efi
RUN pesign -h -P -i /shimx64.efi
RUN pesign -h -P -i /usr/share/shim/$SHIM_VERSION/ia32/shimia32.efi
RUN pesign -h -P -i /shimia32.efi
RUN sha256sum /usr/share/shim/$SHIM_VERSION/x64/shimx64.efi /shimx64.efi /usr/share/shim/$SHIM_VERSION/ia32/shimia32.efi /shimia32.efi

