"""
Gadget Stats class
"""


class GadgetStats(object):
    """
    The Gadget Stats class represents data resulting from the comparison of an original package's gadget set to the
    gadget set of its transformed variant.
    """

    def __init__(self, original, variant):
        """
        GadgetStats constructor
        :param GadgetSet original: Gadget Set from the original package
        :param GadgetSet variant: Gadget Set from the variant package
        """
        self.original = original
        self.variant = variant
        self.name = original.name + " <-> " + variant.name

        self.keptQualityROPCountDiff = len(variant.ROPGadgets) - len(original.ROPGadgets)
        self.keptQualityJOPCountDiff = len(variant.JOPGadgets) - len(original.JOPGadgets)
        self.keptQualityCOPCountDiff = len(variant.COPGadgets) - len(original.COPGadgets)

        self.averageROPQualityDiff = variant.averageROPQuality - original.averageROPQuality
        self.averageJOPQualityDiff = variant.averageJOPQuality - original.averageJOPQuality
        self.averageCOPQualityDiff = variant.averageCOPQuality - original.averageCOPQuality
