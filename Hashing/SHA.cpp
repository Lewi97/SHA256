#include "SHA.h"

std::vector<std::vector<std::uint8_t>> SHA::create_chunks(std::vector<std::uint8_t>& processed_data)
{
    std::vector<std::vector<std::uint8_t>> chunks;
    for (size_t i = 0; i <= processed_data.size() - 64; i += 64)
    {
        std::vector<std::uint8_t> chunk(std::next(processed_data.begin(), i), std::next(processed_data.begin(), i + 64));
        chunks.push_back(chunk);
    }
    return chunks;
}

std::vector<std::uint8_t> SHA::preprocessing(std::string& data)
{
    size_t multiple_of_512 = static_cast<size_t>(std::ceil(static_cast<double>(data.size()) / 64.f)) * 64ULL;
    if (data.size() >= multiple_of_512 - 8) multiple_of_512 += 64;
    std::vector<std::uint8_t> output(multiple_of_512, 0);
    
    size_t i = 0;
    for (const auto& word : data)
        output[i++] = static_cast<std::uint8_t>(word);
   
    output[i] = 0b10000000;

    const size_t L = data.size() * 8ULL;
    i = multiple_of_512 - 8;
    for (size_t t = 8 * 7; t != 0; t -= 8)
        output[i++] = ((L >> t) & 0xFF);

    output[i] = L & 0xFF;

    return output;
}

std::vector<std::uint32_t> SHA::create_message_schedule(std::vector<std::uint8_t>& chunk)
{
    std::vector<std::uint32_t> output(64, 0);
    size_t c_index = 0;
    for (size_t x = 0; x < 16; x++)
    {
        std::uint32_t entry = 0;
        for (int y = 3; y >= 0; y--)
        {
            std::uint32_t new_data = chunk[c_index++];
            new_data <<= 8 * y;
            entry += new_data;
        }
        output[x] = entry;
    }

    for (size_t i = 16; i < 64; i++)
    {
        std::uint32_t s0 = (_rotr(output[i - 15], 7)) ^ (_rotr(output[i - 15], 18)) ^ (output[i - 15] >> 3);
        std::uint32_t s1 = (_rotr(output[i - 2], 17)) ^ (_rotr(output[i - 2], 19)) ^ (output[i - 2] >> 10);
        output[i] = mod_add({ output[i - 16], s0, output[i - 7], s1 }, 4294967296);
    }

    return output;
}

void SHA::compression(std::vector<std::uint32_t>& chunk)
{
    std::uint32_t
        a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7;

    for (size_t i = 0; i < 64; i++)
    {
        std::uint32_t S1 = (_rotr(e, 6)) ^ (_rotr(e, 11)) ^ (_rotr(e, 25));
        std::uint32_t ch = (e & f) ^ ((~e) & g);
        std::uint32_t temp1 = mod_add({ h, S1, ch, k[i], chunk[i] }, 4294967296);
        std::uint32_t S0 = (_rotr(a, 2)) ^ (_rotr(a, 13)) ^ (_rotr(a, 22));
        std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t temp2 = mod_add({ S0, maj }, 4294967296);
        h = g;
        g = f;
        f = e;
        e = mod_add({ d, temp1 }, 4294967296);
        d = c;
        c = b;
        b = a;
        a = mod_add({ temp1, temp2 }, 4294967296);
    }

    h0 = mod_add({h0, a}, 4294967296);
    h1 = mod_add({h1, b}, 4294967296);
    h2 = mod_add({h2, c}, 4294967296);
    h3 = mod_add({h3, d}, 4294967296);
    h4 = mod_add({h4, e}, 4294967296);
    h5 = mod_add({h5, f}, 4294967296);
    h6 = mod_add({h6, g}, 4294967296);
    h7 = mod_add({h7, h}, 4294967296);
}

void SHA::reset()
{
    h0 = 0x6a09e667;
    h1 = 0xbb67ae85;
    h2 = 0x3c6ef372;
    h3 = 0xa54ff53a;
    h4 = 0x510e527f;
    h5 = 0x9b05688c;
    h6 = 0x1f83d9ab;
    h7 = 0x5be0cd19;
}

std::string SHA::finalize()
{
    std::stringstream ss;
    ss 
        << std::hex << h0
        << std::hex << h1
        << std::hex << h2
        << std::hex << h3
        << std::hex << h4
        << std::hex << h5
        << std::hex << h6
        << std::hex << h7;
    return ss.str();
}

std::string SHA::hash(std::string data)
{  
    auto binary = preprocessing(data);
    auto chunks = create_chunks(binary);

    for (auto& chunk : chunks)
    {
        auto schedule = create_message_schedule(chunk);
        compression(schedule);
    }

    const auto ret_val = finalize();
    reset();
    return ret_val;
}
