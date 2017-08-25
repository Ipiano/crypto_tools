$(if $(libcryptool_included),,\
	$(eval libcryptool_included = true)\
	$(eval include $(PROJECT_ROOT)/libcryptool/libcryptool.mk)\
)