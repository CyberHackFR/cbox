from flask_wtf import FlaskForm
from wtforms_alchemy import ModelForm
from .models import Network, NetworkType, System, SystemType, BOX4security
from wtforms import SelectMultipleField, SelectField


class NetworkForm(ModelForm, FlaskForm):
    """Form for Network model."""
    class Meta:
        model = Network
    types = SelectMultipleField(
        'Type-Réseau',
        coerce=int
    )
    scancategory_id = SelectField(
        'Scan-Catégorie',
        coerce=int
    )


class NetworkTypeForm(ModelForm, FlaskForm):
    """Form for NetworkType model."""
    class Meta:
        model = NetworkType


class SystemForm(ModelForm, FlaskForm):
    """Form for NetworkType model."""
    class Meta:
        model = System
    types = SelectMultipleField(
        'Type-Système',
        coerce=int
    )
    network_id = SelectField(
        'Réseau',
        coerce=int
    )


class BOX4sForm(ModelForm, FlaskForm):
    """Form for BOX4s."""
    class Meta:
        model = BOX4security
    dns_id = SelectField(
        'DNS-Server',
        coerce=int
    )
    gateway_id = SelectField(
        'Gateway',
        coerce=int
    )
    network_id = SelectField(
        'Réseau',
        coerce=int
    )


class SystemTypeForm(ModelForm, FlaskForm):
    """Form for SystemType model."""
    class Meta:
        model = SystemType
