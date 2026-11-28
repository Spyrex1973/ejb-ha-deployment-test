import importlib.util, pathlib, unittest
spec=importlib.util.spec_from_file_location("writer_inspector",pathlib.Path(__file__).with_name("inspect.py"))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_alias(self):
  a,b,c=list(m.mounts(["1 0 8:1 /media/Music /music ro - ext4 /dev/x rw","2 0 8:1 /media /alias rw - ext4 /dev/x rw","3 0 8:2 /media /other rw - ext4 /dev/y rw"]))
  self.assertTrue(m.related(a,b));self.assertFalse(m.related(a,c));self.assertFalse(a["rw"])
 def test_escaped(self):
  a=next(m.mounts([r"1 0 8:1 /media/My\040Music /music rw - ext4 /dev/x ro"]))
  self.assertEqual(a["root"],"/media/My Music");self.assertFalse(a["rw"])
 def test_incomplete(self):
  self.assertFalse(m.inspect()["complete"])
