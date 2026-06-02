module top (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        debug_mode_i,
    input  logic        bus_we_i,
    input  logic [7:0]  bus_addr_i,
    input  logic [31:0] bus_wdata_i,
    output logic [31:0] secret_o
);

    logic auth_valid;

    auth_ctrl u_auth_ctrl (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .debug_mode_i(debug_mode_i),
        .auth_valid_o(auth_valid)
    );

    protected_regs u_protected_regs (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .bus_we_i(bus_we_i),
        .bus_addr_i(bus_addr_i),
        .bus_wdata_i(bus_wdata_i),
        .auth_valid_i(auth_valid),
        .secret_o(secret_o)
    );

endmodule

