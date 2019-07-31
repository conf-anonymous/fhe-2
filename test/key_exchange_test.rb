require "minitest/autorun"
require Dir.pwd + "/x"

class TestKeyExchange < Minitest::Test
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

  def test_party_identification
    pr,pu = X::KeyExchange.party_identification(@x)

    assert_equal X::Multivector2Dff, pr.class
    assert_equal X::Multivector2Dff, pu.class
  end

  def test_public_communication_identifier
    pr1,pu1 = X::KeyExchange.party_identification(@x)
    pr2,pu2 = X::KeyExchange.party_identification(@x)

    g = X::KeyExchange.public_communication_identifier(pu1,pu2)

    assert_equal pu1.gp(pu2).data, g.data
  end

  def test_subkey
    pr1,pu1 = X::KeyExchange.party_identification(@x)
    pr2,pu2 = X::KeyExchange.party_identification(@x)

    g = X::KeyExchange.public_communication_identifier(pu1,pu2)

    subk1 = X::KeyExchange.subkey(pr1,g,1)
    subk2 = X::KeyExchange.subkey(pr2,g,2)

    assert_equal pr1.gp(g).data, subk1.data
    assert_equal g.gp(pr2).data, subk2.data
  end

  def test_exchange
    # exchange(subk,pr,g,i)

    pr1,pu1 = X::KeyExchange.party_identification(@x)
    pr2,pu2 = X::KeyExchange.party_identification(@x)

    g = X::KeyExchange.public_communication_identifier(pu1,pu2)

    subk1 = X::KeyExchange.subkey(pr1,g,1)
    subk2 = X::KeyExchange.subkey(pr2,g,2)

    k_from_1 = X::KeyExchange.exchange(subk2,pr1,g,1)
    k_from_2 = X::KeyExchange.exchange(subk1,pr2,g,2)

    assert_equal pr1.gp(subk2).gp(g).add(g).data, k_from_1.data
    assert_equal subk1.gp(pr2).gp(g).add(g).data, k_from_1.data
    assert_equal k_from_1.data, k_from_2.data
  end
end
