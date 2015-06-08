
export PACKAGENAME=httpunit
export PKGRELEASE=99
export PKGVERSION=1.0.0

all: packages list

packages:
	./mk_rpm_fpmdir $(PACKAGENAME) mk_rpm_fpmdir.$(PACKAGENAME).txt

list:
	rpm -lpq /home/tlimoncelli/rpmbuild-$(PACKAGENAME)/$(PACKAGENAME)-$(PKGVERSION)-$(PKGRELEASE).x86_64.rpm

