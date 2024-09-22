"""Methods for deprecating old names for arguments or attributes."""
import warnings
import inspect
from functools import wraps


def deprecated_class_name(old_name, warn=
    "Class name '{old_name}' is deprecated, please use '{new_name}'"):
    """
    Class decorator to deprecate a use of class.

    :param str old_name: the deprecated name that will be registered, but
       will raise warnings if used.

    :param str warn: DeprecationWarning format string for informing the
       user what is the current class name, uses 'old_name' for the deprecated
       keyword name and the 'new_name' for the current one.
       Example: "Old name: {old_nam}, use '{new_name}' instead".
    """
    pass


def deprecated_params(names, warn=
    "Param name '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to translate obsolete names and warn about their use.

    :param dict names: dictionary with pairs of new_name: old_name
        that will be used for translating obsolete param names to new names

    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    pass


def deprecated_instance_attrs(names, warn=
    "Attribute '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to deprecate class instance attributes.

    Translates all names in `names` to use new names and emits warnings
    if the translation was necessary. Does apply only to instance variables
    and attributes (won't modify behaviour of class variables, static methods,
    etc.

    :param dict names: dictionary with paris of new_name: old_name that will
        be used to translate the calls
    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    pass


def deprecated_attrs(names, warn=
    "Attribute '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to deprecate all specified attributes in class.

    Translates all names in `names` to use new names and emits warnings
    if the translation was necessary.

    Note: uses metaclass magic so is incompatible with other metaclass uses

    :param dict names: dictionary with paris of new_name: old_name that will
        be used to translate the calls
    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    pass


def deprecated_method(message):
    """Decorator for deprecating methods.

    :param ste message: The message you want to display.
    """
    pass
