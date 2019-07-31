require "minitest/autorun"
require Dir.pwd + "/x"

class TestKeyUpdate < Minitest::Test
  def setup
    @x = X::FHE.new(4,128)
    @p1 = @x.p1
    @p2 = @x.p2
    @p3 = @x.p3
    @p4 = @x.p4

    @k1 = @x.k1

    @q = @x.q
    @e = @x.e
  end

  def test_generate
    x_copy = @x.dup

    assert_nil x_copy.t1
    assert_nil x_copy.t2

    x_copy = X::KeyUpdate.generate(x_copy,nil)

    assert !x_copy.t1.nil?
    assert !x_copy.t2.nil?

    assert x_copy.k1 != @x.k1
  end

  def test_update
    m1 = X::FHE.random_number(8)
    m2 = X::FHE.random_number(8)

    c1 = @x.encrypt(m1)
    c2 = @x.encrypt(m2)

    x_copy = @x.dup
    x_copy = X::KeyUpdate.generate(x_copy,nil)

    c1_copy = X::KeyUpdate.update(c1,x_copy)
    c2_copy = X::KeyUpdate.update(c2,x_copy)

    assert c1.data != c1_copy.data
    assert c2.data != c2_copy.data
    assert m1 != @x.decrypt(c1_copy)
    assert m2 != @x.decrypt(c2_copy)
    assert_equal m1, x_copy.decrypt(c1_copy)
    assert_equal m2, x_copy.decrypt(c2_copy)
  end

  end
