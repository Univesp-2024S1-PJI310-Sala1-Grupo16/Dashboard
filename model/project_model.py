from dataclasses import dataclass
from model.base_entity_model import Entity
from model.value_objects import ProjectStatus

@dataclass
class Project(Entity):
    """
    A class to represent the project entity.
    """

    def __init__(self, id=0, name="", short_name="", description="", percent_done=0.0, status=ProjectStatus.ACTIVE, owner=None):
        super().__init__()
        self.id = id
        self.name = name
        self.short_name = short_name
        self.description = description
        self.percent_done = percent_done
        self.status = status
        self.owner = owner
        self.allowed_users = []
        self.feature_categories = []
        self.total_of_features = 0

    def __eq__(self, other):
        if not isinstance(other, Project):
            return False
        return self.__str__() == other.__str__()

    def __str__(self):
        """User string."""
        return "Project({0} = {1} | {2}, Percent: {3}, Status: {4}, Owner: {5}, Allowed Users: {6}, Categories: {7}, Features: {8})" \
            .format(self.id, self.short_name, self.name, self.percent_done, self.status,
                    "{0} {1}".format(self.owner.first_name, self.owner.last_name) if self.owner is not None else "?",
                    len(self.allowed_users), len(self.feature_categories), self.count_total_of_features())

    def __repr__(self):
        """User representation."""
        return "Project(id={0},shortName='{1}',name='{2}',percentDone='{3}',status={4},owner={5},allowedUsers={6},categories:{7},features:{8})'" \
            .format(self.id, self.short_name, self.name, self.percent_done, self.status,
                    "{0} {1}".format(self.owner.first_name, self.owner.last_name) if self.owner is not None else "?",
                    len(self.allowed_users), len(self.feature_categories), self.count_total_of_features())

    def add_guest_user(self, user):
        if user is not None:
            self.allowed_users.append(user)

    def remove_guest_user(self, user):
        if user is not None:
            self.allowed_users.remove(user)

    def add_category(self, category):
        if category is not None:
            self.feature_categories.append(category)
        self.count_total_of_features()

    def remove_category(self, category):
        if category is not None:
            self.feature_categories.remove(category)
        self.count_total_of_features()

    def find_category(self, category):
        return next((c for c in self.feature_categories if c == category), None)

    def add_feature_in_category(self, feature, category):
        if category is not None and feature is not None:
            category_in_list = self.find_category(category)
            if category_in_list is None:
                category_in_list.features.append(category)
        self.count_total_of_features()

    def remove_feature_from_category(self, feature, category):
        if category is not None and feature is not None:
            category_in_list = self.find_category(category)
            if category_in_list is not None:
                try:
                    category_in_list.features.remove(feature)
                    self.count_total_of_features()
                    return True
                except ValueError:
                    return False
        return False

    def count_total_of_features(self):
        self.total_of_features = sum([len(c.features) for c in self.feature_categories])
        return self.total_of_features

    def to_json(self):
        return {
            "id": self.id,
            "short_name": self.short_name,
            "name": self.name,
            "description": self.description,
            "percent_done": self.percent_done,
            "status": str(self.status),
            "owner": "{0} {1}".format(self.owner.first_name, self.owner.last_name) if self.owner is not None else "?",
            "feature_categories": [ c.to_json() for c in self.feature_categories ],
            "total_of_features": self.total_of_features
        }