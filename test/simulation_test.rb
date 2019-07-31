require "minitest/autorun"
require Dir.pwd + "/x"

class TestSimulation < Minitest::Test
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

  def test_simulation
    m1 = X::FHE.random_number(8)
    m2 = X::FHE.random_number(8)
    m3 = X::FHE.random_number(8)
    m4 = X::FHE.random_number(8)
    m5 = X::FHE.random_number(8)

    c1 = @x.encrypt(m1)
    c2 = @x.encrypt(m2)
    c3 = @x.encrypt(m3)
    c4 = @x.encrypt(m4)
    c5 = @x.encrypt(m5)

    pr1,pu1 = X::KeyExchange.party_identification(@x)
    pr2,pu2 = X::KeyExchange.party_identification(@x)

    g = X::KeyExchange.public_communication_identifier(pu1,pu2)

    subk1 = X::KeyExchange.subkey(pr1,g,1)
    subk2 = X::KeyExchange.subkey(pr2,g,2)

    k_from_1 = X::KeyExchange.exchange(subk2,pr1,g,1)
    k_from_2 = X::KeyExchange.exchange(subk1,pr2,g,2)

    # party 1 adds all the ciphertexts

    res_1 = c1 + c2 + c3 + c4 + c5

    # party 1 performs a mixed operation

    res_2 = (c1 * c2) + c3 + c4 + c5

    # party 1 uses the key update protocol to
    # generate tokens that will be used
    # for updating the secret key multivectors
    # of consolidated data
    x_copy = @x.dup
    x_copy = X::KeyUpdate.generate(x_copy,k_from_1)

    # party 1 updates the secret key of res_1 and res_2

    res_1 = X::KeyUpdate.update(res_1,x_copy)
    res_2 = X::KeyUpdate.update(res_2,x_copy)

    # now party 2 can decrypt res_1 and res_2

    res_1_d = x_copy.decrypt(res_1)
    res_2_d = x_copy.decrypt(res_2)

    assert_equal x_copy.k1.data, k_from_1.data
    assert_equal m1 + m2 + m3 + m4 + m5, res_1_d
    assert_equal (m1 * m2) + m3 + m4 + m5, res_2_d
  end
end
