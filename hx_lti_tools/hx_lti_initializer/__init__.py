"""
Default settings for the LTI Initializer

Should set up all things needed for the Annotation tool to be set up including
the url for the tool to be accessed and for any other variables to be stored.
"""

from django.conf import settings


def setconf(name, default_value):
    """
    set default value in django.conf.settings
    """
    value = getattr(settings, name, default_value)
    setattr(settings, name, value)

# once in production, make sure to turn this to false
setconf('LTI_DEBUG', True)

# change the url to the proper point to verify they are trying to
# access the correct location
setconf('CONSUMER_URL', 'http://54.69.120.77:8000/lti_init/launch_lti/')

# note that consumer key will be visible via the request
setconf('CONSUMER_KEY', '123key')

# the secret token will be encoded in the request.
# Only places visible are here and the secret given to the LTI consumer,
# in other words, keep it hidden!
setconf('LTI_SECRET', 'secret')

# needs context_id, collection_id, and object_ids to open correct item in tool
setconf('LTI_COURSE_ID', 'context_id')
setconf('LTI_COLLECTION_ID', 'custom_collection_id')
setconf('LTI_OBJECT_IDS', 'custom_object_ids')
setconf('LTI_VIEW_TYPE', 'custom_view_type')
setconf('LTI_CANVAS_ID', 'custom_canvas_id')

# collects roles as user needs to be an admin in order to create a profile
setconf('LTI_ROLES', 'roles')

# should be changed depending on platform roles, these are set up for edX
setconf('ADMIN_ROLES', {'Administrator', 'Instructor'})

# settings for Annotation Server
setconf('DB_API_KEY', 'af17fcb6-ae16-42b7-97f6-b2d1b2d66226')
