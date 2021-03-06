"""
Admin set up for the LTI Initializer

The initializer needs to set up a profile. This is the one thing consistent
throughout the LTI. Even courses is only related via the target objects.
"""

from django.contrib import admin
from hx_lti_initializer.models import LTIProfile, LTICourse


class LTIProfileAdmin(admin.ModelAdmin):
    pass

admin.site.register(LTIProfile, LTIProfileAdmin)
admin.site.register(LTICourse)
