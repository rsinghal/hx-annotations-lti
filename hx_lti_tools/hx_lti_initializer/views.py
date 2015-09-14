"""
This will launch the LTI Annotation tool.

This is basically the controller part of the app. It will set up the tool provider, create/retrive the user and pass along any other information that will be rendered to the access/init screen to the user. 
"""

from ims_lti_py.tool_provider import DjangoToolProvider
from django.http import HttpResponseRedirect
from django.template import RequestContext

from django.core.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404, render_to_response, render
from django.contrib.auth import login
from django.conf import settings
from django.contrib import messages

from hx_lti_initializer.models import LTIProfile, LTICourse

from models import *
from utils import *
from urlparse import urlparse
import sys

def validate_request(req):
    """
    Validates the request in order to permit or deny access to the LTI tool.
    """
    # print out the request to the terminal window if in debug mode
    # this item is set in the settings, in the __init__.py file
    if settings.LTI_DEBUG:
        for item in req.POST:
            debug_printer('DEBUG - %s: %s \r' % (item, req.POST[item]))
    
    # verifies that request contains the information needed
    if 'oauth_consumer_key' not in req.POST:
        debug_printer('DEBUG - Consumer Key was not present in request.')
        raise PermissionDenied()
    if 'user_id' not in req.POST:
        debug_printer('DEBUG - Anonymous ID was not present in request.')
        raise PermissionDenied()
   # if 'lis_person_sourcedid' not in req.POST:
   #     debug_printer('DEBUG - Username was not present in request.')
   #     raise PermissionDenied()
   # if 'lis_person_contact_email_primary' not in req.POST:
   #     debug_printer('DEBUG - User Email was not present in request.')
   #     raise PermissionDenied()

def initialize_lti_tool_provider(req):
    """
    """
    # get the consumer key and secret from settings (__init__.py file)
    # will be used to compare against request to validate the tool init
    consumer_key = settings.CONSUMER_KEY
    secret = settings.LTI_SECRET
    
    # use the function from ims_lti_py app to verify and initialize tool
    provider = DjangoToolProvider(consumer_key, secret, req.POST)
    
    # now validate the tool via the valid_request function
    try:
        # this means that request was well formed but invalid
        if provider.valid_request(req) == False:
            #debug_printer("DEBUG - LTI Exception: Not a valid request.")
            raise PermissionDenied()
    except:
        raise PermissionDenied()
    return provider

def create_new_user(username, email, roles):
    # now create the user and LTIProfile with the above information
    user = User.objects.create_user(lti_username, email)
    user.set_unusable_password()
    user.is_superuser = False
    user.is_staff = False

    for admin_role in settings.ADMIN_ROLES:
        for user_role in roles:
                if admin_role.lower() == user_role.lower():
                    user.is_superuser = True
                    user.is_staff = True
    user.save()
    debug_printer('DEBUG - User was just created')
    
    # pull the profile automatically created once the user was above
    lti_profile = LTIProfile.objects.get(user=user)
    
    lti_profile.anon_id = anon_id
    lti_profile.roles = (",").join(all_user_roles)
    lti_profile.save()
    
    return user, lti_profile

@csrf_exempt
def launch_lti(request):
    """
    Gets a request from an LTI consumer.
    Passes along information to render a welcome screen to the user.
    """
    
    validate_request(request)
    tool_provider = initialize_lti_tool_provider(request)
    
    # collect anonymous_id and consumer key in order to fetch LTIProfile
    # if it exists, we initialize the tool otherwise, we create a new user
    consumer_key_requested = request.POST['oauth_consumer_key']
    anon_id = '%s:%s' % (consumer_key_requested, get_lti_value('user_id', tool_provider))
    
    course = get_lti_value(settings.LTI_COURSE_ID, tool_provider)
    debug_printer('DEBUG - Found course being accessed: %s' % course)
    collection = get_lti_value(settings.LTI_COLLECTION_ID, tool_provider)
    # objects to load into mirador
    layout_param = get_lti_value(settings.LTI_LAYOUT, tool_provider)
    if layout_param:
        layout = layout_param
    else:
        layout = "1x1"

    object_ids = get_lti_value(settings.LTI_OBJECT_IDS, tool_provider)
    objects = []
    if object_ids:
        objects = object_ids.split(';')
    # window specific parameters
    view_type = get_lti_value(settings.LTI_VIEW_TYPE, tool_provider)
    if not view_type:
        view_type = "ImageView"
    canvas_ids = get_lti_value(settings.LTI_CANVAS_ID, tool_provider)
    if canvas_ids is None:
        canvas_ids = get_lti_value(settings.LTI_CANVAS_IDS, tool_provider)
    canvases = []
    if canvas_ids:
        canvases = canvas_ids.split(';')
    object_canvas_ids = {}
    for object in objects:
        for canvas in canvases:
            if object in canvas:
                object_canvas_ids[object] = canvas

    # annotation parameters
    show_annotations = get_lti_value(settings.LTI_SHOW_ANNOTATIONS, tool_provider)
    if not show_annotations or show_annotations.lower() != 'false':
        show_annotations = 'true'
    else:
        show_annotations = show_annotations.lower()

    show_annotation_creation = get_lti_value(settings.LTI_SHOW_ANNOTATION_CREATION, tool_provider)
    if not show_annotation_creation or show_annotation_creation.lower() != 'false':
        show_annotation_creation = 'true'
    else:
        show_annotation_creation = show_annotation_creation.lower()

    # print out custom parameters
    debug_printer('DEBUG - Found object ids in request: %s' % ', '.join(objects))
    debug_printer('DEBUG - Found view type in request: %s' % view_type)
    if canvases:
        debug_printer('DEBUG - Found canvas id in request: %s' % ', '.join(object_canvas_ids))
     
    user_id = get_lti_value('user_id', tool_provider)
    debug_printer('DEBUG - Found anonymous ID in request: %s' % user_id)
    roles = get_lti_value(settings.LTI_ROLES, tool_provider)
    username = get_lti_value('lis_person_sourcedid', tool_provider)
    if len(set(settings.ADMIN_ROLES).intersection(set(roles))) > 0:
        if username is None:
            username = "Instructor"
        else:
            str(username) + " " + 'Instructor'
    if username is None:
        username = user_id[:10]

    # add x-frame-allowed header, rather than doing it in Apache
    x_frame_allowed = False
    parsed_uri = urlparse(request.META.get('HTTP_REFERER'))
    domain = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_uri)
    for item in settings.X_FRAME_ALLOWED_SITES:
        if domain.endswith(item):
            x_frame_allowed = True
            break

    target_type = 'ig'
    response = render(request, '%s/detail.html' % target_type, {
        'username'  : username,
        'user_id'   : user_id,
        'roles'     : roles,
        'collection': collection,
        'course'    : course,
        'layout'    : layout,
        'objects'   : objects,
        'view_type' : view_type,
        'canvas_id' : object_canvas_ids,
        'token'     : retrieve_token(user_id, ''),
        'show_annotations' : show_annotations,
        'show_annotation_creation' : show_annotation_creation
    })

    if not x_frame_allowed:
        response['X-Frame-Options'] = "DENY"
    else :
        response['X-Frame-Options'] = "ALLOW FROM " + domain
    return response
    
    try:
        # try to get the profile via the anon id
        lti_profile = LTIProfile.objects.get(anon_id=anon_id)
        debug_printer('DEBUG - LTI Profile was found via anonymous id.')
    
    except LTIProfile.DoesNotExist:
        debug_printer('DEBUG - LTI Profile not found. New User to be created.')
        
        # gather the necessary data from the LTI initialization request
        email = get_lti_value('lis_person_contact_email_primary', tool_provider)
        lti_username = get_lti_value('lis_person_sourcedid', tool_provider)
        
        # checks to see if email and username were not passed in
        # cannot create a user without them
        if not email or not lti_username:
            debug_printer('DEBUG - Email and/or user_id not found in post.')
            raise PermissionDenied()
        
        # checks to see if roles were passed in. Defaults to student role.
        if settings.ALL_ROLES:
            all_user_roles = []
            
            if not roles:
                debug_printer('DEBUG - ALL_ROLES is set but user was not passed in any roles via the request. Defaults to student.')
                all_user_roles += "Student"
            
            else:
                # makes sure that roles is a list and not just a string
                if not isinstance(roles, list):
                    roles = [roles]
                all_user_roles += roles
            
            # checks to make sure that role is actually allowed/expected
            role_allowed = False
            for role_type in settings.ALL_ROLES:
                for user_role in roles:
                    if role_type.lower() == user_role.lower():
                        role_allowed = True
            
            # if role is not allowed then denied (problem with platform)
            # if role is missing, default to Student (problem with request)
            if not role_allowed:
                debug_printer('DEBUG - User does not have an acceptable role. Check with platform.')
                raise PermissionedDenied()
            else:
                debug_printer('DEBUG - User had an acceptable role: %s' % all_user_roles)
        
        user, lti_profile = create_new_user(lti_username, email, roles)
    
    # now it's time to deal with the course_id it does not associate
    # with users as they can flow in and out in a MOOC
    try:
        debug_printer('DEBUG - Course was found %s' % course)
        course_object = LTICourse.get_course_by_id(course)
    
    except LTICourse.DoesNotExist:
        # this should only happen if an instructor is trying to access the 
        # tool from a different course
        debug_printer('DEBUG - Course %s was NOT found. Will be created.' %course)
        message_error = "Sorry, the course you are trying to reach does not exist."
        messages.error(request, message_error)
        if 'Administrator' in roles:
            # if the user is an administrator, the missing course is created
            # otherwise, it will just display an error message
            message_error = "Because you are an instructor, a course has been created for you, edit it below to add a proper name."
            messages.warning(request, message_error)
            course_object = LTICourse.create_course(course, lti_profile)
    
    # get all the courses the user is a part of
    courses_for_user = LTICourse.get_courses_of_user(lti_profile, course_object)
    
    # then gets all the files associated with the courses 
    files_in_courses = TOD_Implementation.get_dict_of_files_from_courses(lti_profile, courses_for_user)
    
    # logs the user in
    lti_profile.user.backend = 'django.contrib.auth.backends.ModelBackend'
    login(request, lti_profile.user)
    
    # then renders the page using the template
    return render(request, 'hx_lti_initializer/testpage2.html', {'user': lti_profile.user, 'email': lti_profile.user.email, 'user_id': lti_profile.user.get_username(), 'roles': lti_profile.roles, 'courses': courses_for_user, 'files': files_in_courses})