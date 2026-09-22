from django import forms
from .models import ContactMessage


class ContactForm(forms.ModelForm):
    name = forms.CharField(max_length=150)
    email = forms.EmailField(max_length=254)
    subject = forms.CharField(max_length=200)
    message = forms.CharField(min_length=10, max_length=8000, widget=forms.Textarea)

    class Meta:
        model = ContactMessage
        fields = ["name", "email", "subject", "message"]


class SuggestionForm(forms.ModelForm):
    category = forms.ChoiceField(
        choices=[
            ("feature", "Feature request"),
            ("usability", "Usability"),
            ("documentation", "Documentation"),
            ("other", "Other"),
        ]
    )
    name = forms.CharField(max_length=150, required=False)
    email = forms.EmailField(max_length=254, required=False)
    message = forms.CharField(
        label="Suggestion", min_length=10, max_length=8000, widget=forms.Textarea
    )

    class Meta:
        model = ContactMessage
        fields = ["category", "name", "email", "message"]
